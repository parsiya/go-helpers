# Go Helpers
I got tired of creating the same utilities in my Go code. `Go Helpers` is the Go
package containing most of these utility functions.

Import and use individual sub-packages, not the top-level package.

See godoc:

## TODO
1. Refactor big functions in certhelper. Create a struct with certificate and key:
    1. Use variadic functional options?
        * https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
    2. Create a struct of inputs and pass that struct to the function as input?
        * https://godoc.org/github.com/aws/aws-sdk-go/service/s3
        * Probably better?

## License
MIT. See [LICENSE](LICENSE) for details.