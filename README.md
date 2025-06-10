Go Unbound
-----------

Use unbound-control from a Go Library.

## Quick start

When certificate authentication is not enabled:
```go
client, err := NewClient("unix:///run/unbound.sock")
```

When certificate authentication is enabled:
```go
client, err := NewClient("unix:///run/unbound.sock",
                                WithServerCertificatesFile("/path/to/ca.pem"),
                                WithControlCertificatesFile("/path/to/client.key"),
                                WithControlPrivateKeyFile("/path/to/client.pem"))
```

If you are using TCP the address must be prefixed by `tcp://`.

## Documentation

See documentation [here](https://pkg.go.dev/github.com/guillomep/go-unbound).

## Development

The basic development tasks are provided by make. Run `make help` to see the
available targets.

## Contributing

You can help this project by giving time to fill issues or creating pull requests, or if you don't have time you can always buy me a coffee.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/guillomep)

*BTC*: bc1q8c0q9u5qczxrmj9wx6ukg7a2cnxhea5xs4rav9

*LTC*: ltc1qdudg5ralpptu7clr0ruklfmr06vlgl8vdzp0fj
