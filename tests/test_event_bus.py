# 80PWNER — by Anas Mahfouz (The80)

from eightypwner.core.event_bus import BINARY_LOADED, EventBus


def test_publish_reaches_subscriber():
    bus = EventBus()
    seen = []
    bus.subscribe(BINARY_LOADED, lambda t, p: seen.append((t, p)))
    bus.publish(BINARY_LOADED, {"path": "/bin/ls"})
    assert seen == [(BINARY_LOADED, {"path": "/bin/ls"})]


def test_wildcard_subscription():
    bus = EventBus()
    seen = []
    bus.subscribe("*", lambda t, p: seen.append(t))
    bus.publish("anything", 1)
    bus.publish("other", 2)
    assert seen == ["anything", "other"]


def test_unsubscribe_stops_delivery():
    bus = EventBus()
    seen = []
    stop = bus.subscribe("x", lambda t, p: seen.append(p))
    stop()
    bus.publish("x", 42)
    assert seen == []


def test_failing_subscriber_does_not_break_others():
    bus = EventBus()
    seen = []

    def boom(t, p):
        raise RuntimeError("boom")

    bus.subscribe("x", boom)
    bus.subscribe("x", lambda t, p: seen.append(p))
    bus.publish("x", "alive")
    assert seen == ["alive"]
