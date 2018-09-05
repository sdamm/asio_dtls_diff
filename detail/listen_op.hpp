--- /usr/include/asio/ssl/detail/handshake_op.hpp
+++ /include/asio/ssl/dtls/detail/listen_op.hpp
-  engine::want operator()(engine& eng,
+  ssl::dtls::detail::engine::want operator()(engine& eng,
       asio::error_code& ec,
       std::size_t& bytes_transferred) const
   {
     bytes_transferred = 0;
-    return eng.handshake(type_, ec);
+    ssl::dtls::detail::engine::want result = eng.dtls_listen(ec);
+
+    if(result == ssl::dtls::detail::engine::want_output_and_retry)
+    {
+      result = ssl::dtls::detail::engine::want_output;
+    }
+
+    if(result == ssl::dtls::detail::engine::want_output)
+    {
+      // This is not what we transfered, but allows to indicate a wrong cookie
+      bytes_transferred = 0;
+    }
+
+    return result;
   }
