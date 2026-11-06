import pytest

from website import server


def test_topology_contains_four_vlan_networks():
    result = server.topology()

    assert [vlan["id"] for vlan in result["vlans"]] == [10, 20, 30, 40]
    assert len(result["devices"]) == 11
    assert {service["name"] for service in result["services"]} == {
        "DHCP",
        "Inter-VLAN routing",
        "HTTP",
        "DNS",
    }


def test_packet_tracer_download_link_matches_saved_file():
    page = (server.STATIC / "index.html").read_text(encoding="utf-8")

    assert 'href="/Computer_Networks_Project.pkt"' in page
    assert (server.STATIC / "Computer_Networks_Project.pkt").is_file()


def test_trace_routes_between_vlans():
    result = server.trace_packet(
        {
            "source": "A1",
            "destination": "SERVER",
            "protocol": "TCP",
            "destinationPort": 80,
        }
    )

    assert result["path"] == ["A1", "SW1", "R1", "SW1", "SERVER"]
    assert result["source"]["vlan"] == 10
    assert result["destination"]["vlan"] == 40
    assert result["packet"]["destinationPort"] == 80
    assert result["packet"]["ttlEnd"] == 63


def test_trace_stays_inside_same_vlan():
    result = server.trace_packet(
        {"source": "A1", "destination": "A2", "protocol": "UDP"}
    )

    assert result["path"] == ["A1", "SW1", "A2"]
    assert result["packet"]["destinationPort"] == 53
    assert result["packet"]["ttlEnd"] == 64


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"source": "UNKNOWN", "destination": "A1"},
        {"source": "A1", "destination": "A1"},
        {"source": "A1", "destination": "A2", "protocol": "SCTP"},
        {
            "source": "A1",
            "destination": "SERVER",
            "protocol": "TCP",
            "destinationPort": 0,
        },
    ],
)
def test_invalid_trace_requests_are_rejected(payload):
    with pytest.raises(ValueError):
        server.trace_packet(payload)
