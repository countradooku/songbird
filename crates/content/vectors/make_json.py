# The JSON half of the content vectors, written by hand in protobuf's canonical JSON mapping
# (independently of the Rust types). `cargo test -p songbird-content --test vectors` with
# SONGBIRD_WRITE_VECTORS=1 fills in each vector's hex from the Rust types; tools/content-vectors
# then checks that an independent protobuf compiler encodes this JSON to exactly that hex.
# Run: python3 -I crates/content/vectors/make_json.py > crates/content/vectors/v1/vectors.json
import base64, json

def b(byte, n):
    return base64.b64encode(bytes([byte]) * n).decode()

def ref(a, m):
    return {"author": b(a, 16), "messageId": b(m, 16)}

HEAD = {"version": 1, "messageId": b(0x01, 16), "sentAtMs": "1800000000000"}

def content(**body):
    c = dict(HEAD)
    c.update(body)
    return c

def data(kind, value, **extra):
    d = dict(extra)
    d[kind] = value
    return content(data=d)

def sync(kind, value):
    return content(sync={kind: value})

V = []
def vec(name, message, ty="Content"):
    V.append({"name": name, "type": ty, "message": message, "hex": ""})

vec("text", data("message", {
    "text": {"body": "Hi ￼, see this", "spans": [
        {"start": 0, "length": 2, "style": "STYLE_BOLD"},
        {"start": 3, "length": 3, "mention": b(0x22, 16)}]},
    "quote": {"target": ref(0x22, 0x33), "text": {"body": "earlier"}}},
    expireTimerS=3600))
vec("forwarded_voice_note", data("message", {
    "attachments": [{
        "objectId": b(0x44, 32), "key": b(0x55, 64), "digest": b(0x66, 32), "size": "12345",
        "contentType": "audio/ogg", "durationMs": 4200, "flags": 1,
        "waveform": base64.b64encode(bytes([0x00, 0x40, 0x80, 0xff, 0x80, 0x40, 0x00])).decode(),
        "uploadedAtMs": "1800000000000"}],
    "forwardCount": 5}))
vec("view_once_photo", data("message", {
    "attachments": [{
        "objectId": b(0x77, 32), "key": b(0x88, 64), "digest": b(0x99, 32), "size": "2048",
        "contentType": "image/jpeg", "width": 640, "height": 480, "blurhash": "LEHV6nWB2yk8",
        "caption": "look"}],
    "viewOnce": True}))
vec("contact_location_sticker_preview", data("message", {
    "text": {"body": "meet here https://example.org"},
    "contacts": [{"name": "Ada", "account": b(0x0a, 16), "username": "ada.01",
                  "emails": ["ada@example.org"]}],
    "location": {"latitudeE7": 525200066, "longitudeE7": -1234567, "name": "Berlin"},
    "sticker": {"packId": b(0x05, 16), "packKey": b(0x06, 32), "stickerId": 7,
                "emoji": "\U0001F426"},
    "previews": [{"url": "https://example.org", "title": "Example"}]}))
vec("poll", data("message", {"poll": {
    "question": "Lunch?", "options": ["Pizza", "Sushi", "Salad"], "multipleChoice": True}}))
vec("poll_vote", data("pollVote", {"poll": ref(0x22, 0x33), "options": [0, 2], "counter": "3"}))
vec("poll_close", data("pollClose", {"poll": ref(0x22, 0x33), "heads": [
    {"voter": b(0x22, 16), "counter": "3"}, {"voter": b(0x44, 16), "counter": "1"}]}))
vec("event", data("message", {"event": {
    "title": "Launch", "description": "Rooftop", "startMs": "1800003600000",
    "endMs": "1800010800000", "location": {"name": "Roof"}}}))
vec("rsvp", data("rsvp", {"event": ref(0x22, 0x33), "answer": "ANSWER_GOING", "counter": "1"}))
vec("reaction", data("reaction", {"target": ref(0x22, 0x33), "emoji": "\U0001F44D", "counter": "7"}))
vec("reaction_remove", data("reaction", {"target": ref(0x22, 0x33), "remove": True, "counter": "8"}))
vec("edit", data("edit", {"targetMessageId": b(0x33, 16), "text": {"body": "fixed typo"},
                         "revision": 2}))
vec("delete", data("delete", {"target": ref(0x01, 0x33)}))
vec("pin", data("pin", {"target": ref(0x22, 0x33), "durationS": 604800}, groupId=b(0x99, 16)))
vec("timer_change", data("timerChange", {"expireTimerS": 86400}, expireTimerS=86400))
vec("nudge", data("nudge", {}))
vec("call_event", data("callEvent", {
    "callId": b(0x07, 16), "kind": "KIND_VIDEO", "outcome": "OUTCOME_MISSED",
    "startedAtMs": "1800000000000"}))
vec("group_update", data("groupUpdate", {
    "kind": "KIND_MEMBERS_ADDED", "actor": b(0x22, 16), "subjects": [b(0x44, 16), b(0x55, 16)]},
    groupId=b(0x99, 16)))
vec("chat_policy", data("chatPolicy", {"restrictExport": True, "restrictAutoSave": True}))
vec("receipt_read", content(receipt={
    "kind": "KIND_READ", "messageIds": [b(0x33, 16), b(0x44, 16)], "upTo": b(0x55, 16)}))
vec("typing", content(typing={"started": True, "groupId": b(0x99, 16)}))
vec("request_accept", content(requestResponse={
    "action": "ACTION_ACCEPT", "chat": {"account": b(0x22, 16)}}))
vec("sync_sent", sync("sent", {
    "chat": {"account": b(0x22, 16)}, "content": "@reaction", "frankingKey": b(0x42, 32),
    "storedAtMs": "1800000000123"}))
vec("sync_read", sync("read", {"marks": [{"message": ref(0x22, 0x33), "atMs": "1800000000500"}]}))
vec("sync_viewed", sync("viewed", {"marks": [{"message": ref(0x22, 0x44), "atMs": "1800000000900"}]}))
vec("sync_starred", sync("starred", {"added": [ref(0x22, 0x33)], "removed": [ref(0x44, 0x55)]}))
vec("sync_chat_state", sync("chatState", {"chats": [{
    "chat": {"groupId": b(0x99, 16)}, "archived": True,
    "mutedUntilMs": "18446744073709551615", "pinned": True}]}))
vec("sync_settings", sync("settings", {
    "readReceipts": False, "typingIndicators": True, "defaultExpireTimerS": 604800}))
vec("sync_blocked", sync("blocked", {"accounts": [b(0x66, 16)], "groupIds": [b(0x77, 16)]}))
vec("sync_call_history", sync("callHistory", {"calls": [{
    "callId": b(0x07, 16), "kind": "KIND_AUDIO", "outcome": "OUTCOME_ACCEPTED", "outgoing": True,
    "startedAtMs": "1800000000000", "durationS": 61, "peer": b(0x22, 16)}]}))
vec("sync_request_response", sync("requestResponse", {
    "action": "ACTION_BLOCK", "chat": {"account": b(0x66, 16)}}))
def call(**kind):
    return content(call=dict(callId=b(0x07, 16), **kind))

vec("call_offer_1to1", call(offer={
    "media": "KIND_VIDEO", "callSecret": b(0x42, 32), "ringUntilMs": "1800000060000"}))
vec("call_offer_group", call(offer={
    "media": "KIND_AUDIO", "groupId": b(0x99, 16), "ringUntilMs": "1800000060000"}))
vec("call_answer", call(answer={}))
vec("call_hangup", call(hangup={"reason": "REASON_ANSWERED_ELSEWHERE"}))
vec("call_sender_key", call(senderKey={
    "identity": "0123456789abcdef0123456789abcdef", "keyIndex": 3, "key": b(0x55, 32)}))
# A franked plaintext: the "reaction" content under franking key 32 x 0x42, padded.
vec("plaintext_franked", {"content": "@reaction", "frankingKey": b(0x42, 32)}, ty="PaddedPlaintext")
# Accepting a request: the profile key travels beside the content, never inside it.
vec("plaintext_accept", {"content": "@request_accept", "profileKey": b(0x11, 32)}, ty="PaddedPlaintext")

print(json.dumps({"version": 1, "vectors": V}, indent=1, ensure_ascii=False))
