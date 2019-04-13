#  CryptoLab
## Experiments in iOS and macOS cryptography

Apple’s CommonCrypto library provides core symmetric encryption and other common functions, but uses a low level API that is difficult to use. CryptoLab includes a thin Swift language wrapper around CommonCrypto, then add some convenience methods for ease of use.

Apple’s SecKey API provides high level encryption and other common functions with a mid level CoreFoundation based API. CryptoLab provides a Swift API for both CoreFoundation and higher level access.

CommonCrypto includes functions to support key generation from passwords. CryptoLab includes sample utilities and a macOS app to illustrate password based encryption and message authentication.
