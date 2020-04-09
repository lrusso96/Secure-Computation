# String OT

This is a simple protocol for K 1-out-of-N string OTs.

## Main idea

Alice stores K strings and Bob chooses one of them.

### Limitations

Since this is only a toy protocol, here are some current limitations:

* K is a small constant, a priori shared
* UTF-7 strings are allowed, with a maximum length of 16
* Inputs are hard-coded, as well as all the security parameters

## Dependencies

* [libOte](https://github.com/osu-crypto/libOTe)
