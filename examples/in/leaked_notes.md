# Homelab notes (draft - do not publish yet)

Self-hosted relay, PSK bearer address copied from `tailcat serve` output:

    tcpGFwWCBVY2ioHpUnMd6cNDNWxtyfsw_-U8RSmO_Fk_BdeqWjdmFrWCCyJSyyQfRa6Kone_9khyUEtpeqWS6bvPk6WAHzaUdnnmFxWCAFXOJQ3OS0F7Po_AGur2MGDdjrNpmmO1VQMzCTKCpjoWFygaRhaRkDhWFjY3B1YmFtbVB1YmxpYyBSZWdpb25hToGjYW5kcHViMWFocGRlcnAuZXhhbXBsZS5vcmdhNGwxOTguNTEuMTAwLjc

DNS record I was about to publish for a protected SSH server:

my-box.example.com. 300 IN TXT "tailcat=tcpGFwWCBVY2ioHpUnMd6cNDNWxtyfsw_-U8RSmO_Fk_BdeqWjdmFrWCCyJSyyQfRa6Kone_9khyUEtpeqWS6bvPk6WAHzaUdnnmFxWCAFXOJQ3OS0F7Po_AGur2MGDdjrNpmmO1VQMzCTKCpjoWFygaRhaRkDhWFjY3B1YmFtbVB1YmxpYyBSZWdpb25hToGjYW5kcHViMWFocGRlcnAuZXhhbXBsZS5vcmdhNGwxOTguNTEuMTAwLjc"

Legacy server started with `--psk=false` (safe to publish with --allow):

    tco2FwWCBmqzCyd918T_39QjSXNQ8jkG_jzbxdWcEZYMRmVSPlL2FpAmFrWCDUdAEzMrZvEunY9CkIw0YVc_ItBoYEREFftVnD-2-jFQ
