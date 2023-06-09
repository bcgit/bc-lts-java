/**
 * Experimental implementation of curve25519. Note that the curve implementation is in the short-Weierstrass form,
 * which is not the recommended (nor most suitable) approach. In particular, the input/output conventions are not
 * compliant with standard implementations, and point conversions would be needed to interoperate.
 */
package org.bouncycastle.math.ec.custom.djb;
