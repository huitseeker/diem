// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// NB: We run all tests serially because some tests need to inspect counters to verify certain code
// paths were taken, in absence of other feedback signals. Since counters are static variables (and
// therefore shared across tests), this can sometimes lead to interference and tests being
// deadlocked.

use super::{error::RpcError, *};
use crate::{
    counters::{CANCELED_LABEL, REQUEST_LABEL},
    peer::{PeerNotification, PeerRequest},
    peer_manager::PeerManagerError,
    transport::ConnectionMetadata,
};
use anyhow::anyhow;
use diem_config::network_id::NetworkContext;
use diem_types::PeerId;
use futures::future::join;
use serial_test::serial;
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};

static RPC_PROTOCOL_A: ProtocolId = ProtocolId::ConsensusRpc;
static RPC_PROTOCOL_B: ProtocolId = ProtocolId::HealthCheckerRpc;

fn reset_counters() {
    counters::DIEM_NETWORK_RPC_MESSAGES.reset();
    counters::DIEM_NETWORK_RPC_BYTES.reset();
}

fn start_rpc_actor(
    executor: Handle,
) -> (
    Arc<NetworkContext>,
    channel::Sender<OutboundRpcRequest>,
    channel::Receiver<PeerRequest>,
    channel::Sender<PeerNotification>,
) {
    let network_context = NetworkContext::mock();
    let (peer_reqs_tx, peer_reqs_rx) = channel::new_test(8);
    let (peer_notifs_tx, peer_notifs_rx) = channel::new_test(8);
    let (rpc_requests_tx, rpc_requests_rx) = channel::new_test(8);
    // Reset counters before starting actor.
    reset_counters();
    let connection_metadata = ConnectionMetadata::mock(PeerId::random());
    let rpc = Rpc::new(
        Arc::clone(&network_context),
        PeerHandle::new(network_context.clone(), connection_metadata, peer_reqs_tx),
        rpc_requests_rx,
        peer_notifs_rx,
        10, // max_concurrent_outbound_rpcs
    );
    executor.spawn(rpc.start());
    (
        network_context,
        rpc_requests_tx,
        peer_reqs_rx,
        peer_notifs_tx,
    )
}

async fn expect_two_requests(
    peer_rx: &mut channel::Receiver<PeerRequest>,
    expected_protocol_a: ProtocolId,
    expected_protocol_b: ProtocolId,
    expected_message_a: NetworkMessage,
    expected_message_b: NetworkMessage,
) {
    for _ in 0..2 {
        match peer_rx.next().await.unwrap() {
            PeerRequest::SendMessage(message, protocol, res_tx) => {
                if protocol == expected_protocol_a {
                    assert_eq!(message, expected_message_a);
                } else {
                    assert_eq!(protocol, expected_protocol_b);
                    assert_eq!(message, expected_message_b);
                }
                res_tx.send(Ok(())).unwrap();
            }
            req => panic!("Unexpected PeerRequest: {:?}, expected OpenSubstream", req),
        }
    }
}

async fn expect_successful_send(
    peer_rx: &mut channel::Receiver<PeerRequest>,
    expected_protocol_id: ProtocolId,
    expected_message: NetworkMessage,
) {
    // Return success on the next SendMessage request.
    match peer_rx.next().await.unwrap() {
        PeerRequest::SendMessage(message, protocol_id, res_tx) => {
            assert_eq!(protocol_id, expected_protocol_id);
            assert_eq!(message, expected_message);
            res_tx.send(Ok(())).unwrap();
        }
        req => panic!("Unexpected PeerRequest: {:?}, expected OpenSubstream", req),
    }
}

async fn expect_failed_send(
    peer_rx: &mut channel::Receiver<PeerRequest>,
    expected_protocol_id: ProtocolId,
    expected_message: NetworkMessage,
) {
    // Return failure on the next SendMessage request.
    match peer_rx.next().await.unwrap() {
        PeerRequest::SendMessage(message, protocol_id, res_tx) => {
            assert_eq!(protocol_id, expected_protocol_id);
            assert_eq!(message, expected_message);
            res_tx
                .send(Err(PeerManagerError::Error(anyhow!("failed to send"))))
                .unwrap();
        }
        req => panic!("Unexpected PeerRequest: {:?}, expected OpenSubstream", req),
    }
}

fn create_network_request(
    request_id: RequestId,
    protocol_id: ProtocolId,
    raw_request: Bytes,
) -> NetworkMessage {
    NetworkMessage::RpcRequest(RpcRequest {
        request_id,
        protocol_id,
        priority: Priority::default(),
        raw_request: Vec::from(raw_request.as_ref()),
    })
}

fn create_network_response(request_id: RequestId, raw_response: Bytes) -> NetworkMessage {
    NetworkMessage::RpcResponse(RpcResponse {
        request_id,
        priority: Priority::default(),
        raw_response: Vec::from(raw_response.as_ref()),
    })
}

// Test successful outbound RPC.
// We implement a translating RPC service that translates English -> French.
#[test]
#[serial]
fn outbound_rpc_success() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (_network_context, mut rpc_requests_tx, mut peer_reqs_rx, mut peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id = RPC_PROTOCOL_A;
    let req_data = Bytes::from_static(b"Hello");
    let expected_req_data = req_data.clone();
    let resp_data = Bytes::from_static(b"Bonjour");
    let expected_resp_data = resp_data.clone();

    // Mock messages received and sent by the peer actor.
    let f_mock_peer = async move {
        // Create expected request and response NetworkMessages.
        let request = create_network_request(0, protocol_id, expected_req_data);
        let response = create_network_response(0, resp_data);

        // Successfully send outbound RpcRequest message.
        expect_successful_send(&mut peer_reqs_rx, protocol_id, request).await;
        // Notify about inbound RpcResponse.
        peer_notifs_tx
            .send(PeerNotification::NewMessage(response))
            .await
            .unwrap();
    };

    // Make an outbound rpc request. Listener responds with translated message.
    let f_send_rpc = async move {
        let (res_tx, res_rx) = oneshot::channel();
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id,
                data: req_data.clone(),
                res_tx,
                timeout: Duration::from_millis(100),
            })
            .await
            .unwrap();

        // Wait for success.
        assert_eq!(expected_resp_data, res_rx.await.unwrap().unwrap());
    };

    let f = join(f_send_rpc, f_mock_peer);
    rt.block_on(f);
}

// Test that sending two "concurrent" requests should succeed.
// We implement a translating RPC service that translates English -> Hindi.
#[test]
#[serial]
fn outbound_rpc_concurrent() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (_network_context, mut rpc_requests_tx, mut peer_reqs_rx, mut peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id_a = RPC_PROTOCOL_A;
    let protocol_id_b = RPC_PROTOCOL_B;

    let req_data_a = Bytes::from_static(b"Hello");
    let req_data_b = Bytes::from_static(b"world");
    let expected_req_data_a = req_data_a.clone();
    let expected_req_data_b = req_data_b.clone();

    let resp_data_a = Bytes::from_static(b"namaste");
    let resp_data_b = Bytes::from_static(b"duniya");
    let expected_resp_data_a = resp_data_a.clone();
    let expected_resp_data_b = resp_data_b.clone();

    // Mock messages received and sent by the peer actor.
    let f_mock_peer = async move {
        // Create expected request and response NetworkMessages.
        let request_a = create_network_request(0 as RequestId, protocol_id_a, expected_req_data_a);
        let request_b = create_network_request(1 as RequestId, protocol_id_b, expected_req_data_b);
        let response_a = create_network_response(0 as RequestId, resp_data_a);
        let response_b = create_network_response(1 as RequestId, resp_data_b);

        // Wait for both requests to arrive.
        expect_two_requests(
            &mut peer_reqs_rx,
            protocol_id_a,
            protocol_id_b,
            request_a,
            request_b,
        )
        .await;
        // Send response for second request first.
        peer_notifs_tx
            .send(PeerNotification::NewMessage(response_b))
            .await
            .unwrap();
        // Send response for first request next.
        peer_notifs_tx
            .send(PeerNotification::NewMessage(response_a))
            .await
            .unwrap();
    };

    // Make two outbound RPC requests and wait for both to succeed.
    let f_send_rpc = async move {
        // Send first request.
        let (res_tx_a, res_rx_a) = oneshot::channel();
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id: protocol_id_a,
                data: req_data_a.clone(),
                res_tx: res_tx_a,
                timeout: Duration::from_millis(100),
            })
            .await
            .unwrap();

        // Send second request.
        let (res_tx_b, res_rx_b) = oneshot::channel();
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id: protocol_id_b,
                data: req_data_b.clone(),
                res_tx: res_tx_b,
                timeout: Duration::from_millis(100),
            })
            .await
            .unwrap();

        // Wait for response to second RPC first.
        assert_eq!(expected_resp_data_b, res_rx_b.await.unwrap().unwrap());
        // Wait for response to first RPC next.
        assert_eq!(expected_resp_data_a, res_rx_a.await.unwrap().unwrap());
    };

    let f = join(f_send_rpc, f_mock_peer);
    rt.block_on(f);
}

// Test that outbound rpc calls will timeout if response does not arrive.
#[test]
#[serial]
fn outbound_rpc_timeout() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (_network_context, mut rpc_requests_tx, mut peer_reqs_rx, _peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id = RPC_PROTOCOL_A;
    let req_data = Bytes::from_static(b"hello");
    let message = create_network_request(
        0, // This is the first request.
        protocol_id,
        req_data.clone(),
    );

    let f_mock_peer = expect_successful_send(&mut peer_reqs_rx, protocol_id, message);

    // Make an outbound rpc request. listener does not reply with response within timeout.
    let f_send_rpc = async move {
        let (res_tx, res_rx) = oneshot::channel();
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id,
                data: req_data,
                res_tx,
                timeout: Duration::from_millis(100),
            })
            .await
            .unwrap();

        // Check error is timeout error
        let result: Result<Bytes, RpcError> = res_rx.await.unwrap();
        assert!(matches!(result, Err(RpcError::TimedOut)));
    };

    let f = join(f_mock_peer, f_send_rpc);
    rt.block_on(f);
}

// Test that outbound rpcs can be canceled immediately after request.
#[test]
#[serial]
fn outbound_cancellation_before_send() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (network_context, mut rpc_requests_tx, _peer_reqs_rx, _peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id = RPC_PROTOCOL_A;
    let req_data = Bytes::from_static(b"hello");
    let (res_tx, res_rx) = oneshot::channel();

    // Make an outbound rpc request. listener does not reply with response within timeout.
    let f_send_rpc = async move {
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id,
                data: req_data.clone(),
                res_tx,
                timeout: Duration::from_secs(100), // use a large timeout value.
            })
            .await
            .unwrap();

        // drop res_rx to cancel the rpc request and wait for request to be canceled.
        drop(res_rx);

        while counters::rpc_messages(&network_context, REQUEST_LABEL, CANCELED_LABEL).get() as u64
            != 1
        {
            tokio::time::delay_for(Duration::from_millis(10)).await;
        }
    };
    rt.block_on(f_send_rpc);
}

// Test that outbound rpcs can be canceled before receiving response.
#[test]
#[serial]
fn outbound_cancellation_before_recv() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (network_context, mut rpc_requests_tx, mut peer_reqs_rx, _peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id = RPC_PROTOCOL_A;
    let req_data = Bytes::from_static(b"hello");

    let (res_tx, res_rx) = oneshot::channel();

    // Make an outbound rpc request and then cancel before receiving response.
    let f_send_rpc = async move {
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id,
                data: req_data.clone(),
                res_tx,
                timeout: Duration::from_secs(100), // use a large timeout value.
            })
            .await
            .unwrap();

        let request = create_network_request(0 as RequestId, protocol_id, req_data.clone());

        // mock sending to remote peer.
        expect_successful_send(&mut peer_reqs_rx, protocol_id, request).await;

        // drop res_rx to cancel the rpc request and wait for request to be canceled.
        drop(res_rx);

        while counters::rpc_messages(&network_context, REQUEST_LABEL, CANCELED_LABEL).get() as u64
            != 1
        {
            tokio::time::delay_for(Duration::from_millis(10)).await;
        }
    };
    rt.block_on(f_send_rpc);
}

// Test failure path when request cannot be delivered for outbound RPC.
#[test]
#[serial]
fn outbound_rpc_failed_request_delivery() {
    ::diem_logger::Logger::init_for_testing();

    let mut rt = Runtime::new().unwrap();
    let (_network_context, mut rpc_requests_tx, mut peer_reqs_rx, _peer_notifs_tx) =
        start_rpc_actor(rt.handle().clone());

    let protocol_id = RPC_PROTOCOL_A;
    let req_data = Bytes::from_static(b"hello");
    let request = create_network_request(0 as RequestId, protocol_id, req_data.clone());

    let f_mock_peer = expect_failed_send(&mut peer_reqs_rx, protocol_id, request);

    // Make an outbound rpc request. listener does not reply with response within timeout.
    let f_send_rpc = async move {
        let (res_tx, res_rx) = oneshot::channel();
        rpc_requests_tx
            .send(OutboundRpcRequest {
                protocol_id,
                data: req_data,
                res_tx,
                timeout: Duration::from_millis(100),
            })
            .await
            .unwrap();

        // Check that request fails.
        let result: Result<Bytes, RpcError> = res_rx.await.unwrap();
        assert!(matches!(result, Err(_)));
    };

    let f = join(f_mock_peer, f_send_rpc);
    rt.block_on(f);
}