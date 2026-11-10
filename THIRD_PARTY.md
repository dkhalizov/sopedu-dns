# Third-party notices

## Trademarks

AdGuard, AdGuard Home, Pi-hole, dnsmasq, Unbound, Blocky, Numa and any other
product names in this repository are trademarks of their owners. We use them
only to describe compatibility or to name products in comparisons. sopedu-dns
isn't affiliated with, endorsed by or derived from any of them. We use no
logos.

## Standards

sopedu-dns follows the IETF RFCs cited in the code and docs, mainly
RFC 1035, 2181, 2308, 3597, 4035, 5452, 6891, 7766, 8484 (DoH), 8767
(serve-stale), 8914 and 9520. We don't reproduce their text.

## Blocklists

Blocklists are downloaded at run time and aren't part of this repository.
Each list has its own license; check it before you redistribute one.

## Dependencies

Crates come from crates.io and aren't bundled in the source tree.
`deny.toml` limits them to permissive licenses and MPL-2.0. We generate the
license notices for a binary release with
[cargo-about](https://github.com/EmbarkStudios/cargo-about):

```sh
cargo install cargo-about --locked
cargo about generate about.hbs > THIRD-PARTY-LICENSES.html
```

`about.toml` holds the accepted license list; keep it in sync with `deny.toml`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
