--- /usr/include/asio/ssl/context.hpp
+++ /include/asio/ssl/dtls/context.hpp

@@ -40,8 +41,40 @@
   /// The native handle type of the SSL context.
   typedef SSL_CTX* native_handle_type;
 
+  enum dtls_method
+  {
+    /// Generic DTLS version 1.0
+    dtlsv1,
+
+    /// DTLS version 1.0 client
+    dtlsv1_client,
+
+    /// DTLS version 1.0 server
+    dtlsv1_server,
+
+    /// Generic DTLS version 1.2
+    dtlsv12,
+
+    /// DTLS version 1.2 client
+    dtlsv12_client,
+
+    /// DTLS version 1.2 server
+    dtlsv12_server,
+
+    /// Generic DTLS
+    dtls,
+
+    /// DTLS server
+    dtls_server,
+
+    /// DTLS client
+    dtls_client
+  };
+
+  ASIO_STATIC_CONSTANT(long, cookie_exchange = SSL_OP_COOKIE_EXCHANGE);
+
   /// Constructor.
-  ASIO_DECL explicit context(method m);
+  ASIO_DECL explicit context(dtls_method m);
 
 };
 