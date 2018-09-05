--- /usr/include/asio/ssl/detail/engine.hpp
+++ /include/asio/ssl/dtls/detail/engine.hpp
@@ -64,6 +67,25 @@
   // Get the underlying implementation in the native type.
   ASIO_DECL SSL* native_handle();
 
+  // Set the MTU used for handshaking
+  ASIO_DECL bool set_mtu(int mtu);
+
+  // Set temporary data for cookie validation
+  ASIO_DECL void set_dtls_tmp_data(void* data);
+
+  // Get temporary data for cookie validation
+  ASIO_DECL void* get_dtls_tmp_data();
+
+  // Set Callback for cookie generation
+  ASIO_DECL asio::error_code set_cookie_generate_callback(
+    dtls::detail::cookie_generate_callback_base* callback,
+    asio::error_code& ec);
+
+  // Set Callback for cookie validation
+  ASIO_DECL asio::error_code set_cookie_verify_callback(
+    dtls::detail::cookie_verify_callback_base * callback,
+    asio::error_code& ec);
+
   // Set the peer verification mode.
   ASIO_DECL asio::error_code set_verify_mode(
       verify_mode v, asio::error_code& ec);
@@ -74,7 +96,10 @@
 
   // Set a peer certificate verification callback.
   ASIO_DECL asio::error_code set_verify_callback(
-      verify_callback_base* callback, asio::error_code& ec);
+      ssl::detail::verify_callback_base* callback, asio::error_code& ec);
+
+  // Perform an DTLS_v1_listen to verify the dtls cookie
+  ASIO_DECL want dtls_listen(asio::error_code& ec);
 
   // Perform an SSL handshake using either SSL_connect (client-side) or
   // SSL_accept (server-side).
@@ -114,6 +139,19 @@
   // Callback used when the SSL implementation wants to verify a certificate.
   ASIO_DECL static int verify_callback_function(
       int preverified, X509_STORE_CTX* ctx);
+
+  // Callback used when the SSL implementation wants to generate a DTLS cookie
+  ASIO_DECL static int generate_cookie_function(
+      SSL *ssl, unsigned char *cookie, unsigned int *length);
+
+  // Callback used when the SSL implementation wants to verify a DTLS cookie
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
+  ASIO_DECL static int verify_cookie_function(
+      SSL *ssl, const unsigned char *cookie, unsigned int length);
+#else  //(OPENSSL_VERSION_NUMBER >= 0x10100000L)
+  ASIO_DECL static int verify_cookie_function(
+      SSL *ssl, unsigned char *cookie, unsigned int length);
+#endif //(OPENSSL_VERSION_NUMBER >= 0x10100000L)
 
 #if (OPENSSL_VERSION_NUMBER < 0x10000000L)
   // The SSL_accept function may not be thread safe. This mutex is used to
@@ -128,6 +166,9 @@
       void* data, std::size_t length, asio::error_code& ec,
       std::size_t* bytes_transferred);
 
+  // Adapt the DTLSv1_listen function to the signatoure needed for perform().
+  ASIO_DECL int do_dtls_listen(void*, std::size_t);
+
   // Adapt the SSL_accept function to the signature needed for perform().
   ASIO_DECL int do_accept(void*, std::size_t);
 
