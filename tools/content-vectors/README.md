# content-vectors

Checks the content test vectors (`crates/content/vectors/v*/vectors.json`) against
`crates/content/proto/content.proto` with an independent protobuf compiler (`protox`) and dynamic
messages (`prost-reflect`), decision D-0059. Each vector's JSON is written by hand
(`crates/content/vectors/make_json.py`); its hex comes from the Rust types. Both must agree byte
for byte, and decoding must leave no unknown field.

Not part of the workspace or of any build (it pulls a protobuf compiler that nothing ships with).

```bash
cd tools/content-vectors && cargo run --release
```
