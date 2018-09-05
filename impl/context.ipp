--- /usr/include/asio/ssl/impl/context.ipp
+++ /include/asio/ssl/dtls/impl/context.ipp
@@ -59,252 +60,63 @@
   ~dh_cleanup() { if (p) ::DH_free(p); }
 };
 
-context::context(context::method m)
+context::context(context::dtls_method m)
   : handle_(0)
 {
   ::ERR_clear_error();
 
   switch (m)
   {
-    // SSL v2.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) || defined(OPENSSL_NO_SSL2)
-  case context::sslv2:
-  case context::sslv2_client:
-  case context::sslv2_server:
-    asio::detail::throw_error(
-        asio::error::invalid_argument, "context");
-    break;
-#else // (OPENSSL_VERSION_NUMBER >= 0x10100000L) || defined(OPENSSL_NO_SSL2)
-  case context::sslv2:
-    handle_ = ::SSL_CTX_new(::SSLv2_method());
-    break;
-  case context::sslv2_client:
-    handle_ = ::SSL_CTX_new(::SSLv2_client_method());
-    break;
-  case context::sslv2_server:
-    handle_ = ::SSL_CTX_new(::SSLv2_server_method());
-    break;
-#endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L) || defined(OPENSSL_NO_SSL2)
-
-    // SSL v3.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
-  case context::sslv3:
-    handle_ = ::SSL_CTX_new(::TLS_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, SSL3_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, SSL3_VERSION);
-    }
-    break;
-  case context::sslv3_client:
-    handle_ = ::SSL_CTX_new(::TLS_client_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, SSL3_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, SSL3_VERSION);
-    }
-    break;
-  case context::sslv3_server:
-    handle_ = ::SSL_CTX_new(::TLS_server_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, SSL3_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, SSL3_VERSION);
-    }
-    break;
-#elif defined(OPENSSL_NO_SSL3)
-  case context::sslv3:
-  case context::sslv3_client:
-  case context::sslv3_server:
-    asio::detail::throw_error(
-        asio::error::invalid_argument, "context");
-    break;
-#else // defined(OPENSSL_NO_SSL3)
-  case context::sslv3:
-    handle_ = ::SSL_CTX_new(::SSLv3_method());
-    break;
-  case context::sslv3_client:
-    handle_ = ::SSL_CTX_new(::SSLv3_client_method());
-    break;
-  case context::sslv3_server:
-    handle_ = ::SSL_CTX_new(::SSLv3_server_method());
-    break;
-#endif // defined(OPENSSL_NO_SSL3)
-
-    // TLS v1.0.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
-  case context::tlsv1:
-    handle_ = ::SSL_CTX_new(::TLS_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_VERSION);
-    }
-    break;
-  case context::tlsv1_client:
-    handle_ = ::SSL_CTX_new(::TLS_client_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_VERSION);
-    }
-    break;
-  case context::tlsv1_server:
-    handle_ = ::SSL_CTX_new(::TLS_server_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_VERSION);
-    }
-    break;
-#else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
-  case context::tlsv1:
-    handle_ = ::SSL_CTX_new(::TLSv1_method());
-    break;
-  case context::tlsv1_client:
-    handle_ = ::SSL_CTX_new(::TLSv1_client_method());
-    break;
-  case context::tlsv1_server:
-    handle_ = ::SSL_CTX_new(::TLSv1_server_method());
-    break;
-#endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
-
-    // TLS v1.1.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
-  case context::tlsv11:
-    handle_ = ::SSL_CTX_new(::TLS_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_1_VERSION);
-    }
-    break;
-  case context::tlsv11_client:
-    handle_ = ::SSL_CTX_new(::TLS_client_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_1_VERSION);
-    }
-    break;
-  case context::tlsv11_server:
-    handle_ = ::SSL_CTX_new(::TLS_server_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_1_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_1_VERSION);
-    }
-    break;
-#elif defined(SSL_TXT_TLSV1_1)
-  case context::tlsv11:
-    handle_ = ::SSL_CTX_new(::TLSv1_1_method());
-    break;
-  case context::tlsv11_client:
-    handle_ = ::SSL_CTX_new(::TLSv1_1_client_method());
-    break;
-  case context::tlsv11_server:
-    handle_ = ::SSL_CTX_new(::TLSv1_1_server_method());
-    break;
-#else // defined(SSL_TXT_TLSV1_1)
-  case context::tlsv11:
-  case context::tlsv11_client:
-  case context::tlsv11_server:
-    asio::detail::throw_error(
-        asio::error::invalid_argument, "context");
-    break;
-#endif // defined(SSL_TXT_TLSV1_1)
-
-    // TLS v1.2.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
-  case context::tlsv12:
-    handle_ = ::SSL_CTX_new(::TLS_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_2_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_2_VERSION);
-    }
-    break;
-  case context::tlsv12_client:
-    handle_ = ::SSL_CTX_new(::TLS_client_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_2_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_2_VERSION);
-    }
-    break;
-  case context::tlsv12_server:
-    handle_ = ::SSL_CTX_new(::TLS_server_method());
-    if (handle_)
-    {
-      SSL_CTX_set_min_proto_version(handle_, TLS1_2_VERSION);
-      SSL_CTX_set_max_proto_version(handle_, TLS1_2_VERSION);
-    }
-    break;
-#elif defined(SSL_TXT_TLSV1_1)
-  case context::tlsv12:
-    handle_ = ::SSL_CTX_new(::TLSv1_2_method());
-    break;
-  case context::tlsv12_client:
-    handle_ = ::SSL_CTX_new(::TLSv1_2_client_method());
-    break;
-  case context::tlsv12_server:
-    handle_ = ::SSL_CTX_new(::TLSv1_2_server_method());
-    break;
-#else // defined(SSL_TXT_TLSV1_1)
-  case context::tlsv12:
-  case context::tlsv12_client:
-  case context::tlsv12_server:
-    asio::detail::throw_error(
-        asio::error::invalid_argument, "context");
-    break;
-#endif // defined(SSL_TXT_TLSV1_1)
-
-    // Any supported SSL/TLS version.
-  case context::sslv23:
-    handle_ = ::SSL_CTX_new(::SSLv23_method());
-    break;
-  case context::sslv23_client:
-    handle_ = ::SSL_CTX_new(::SSLv23_client_method());
-    break;
-  case context::sslv23_server:
-    handle_ = ::SSL_CTX_new(::SSLv23_server_method());
-    break;
-
-    // Any supported TLS version.
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
-  case context::tls:
-    handle_ = ::SSL_CTX_new(::TLS_method());
-    if (handle_)
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-    break;
-  case context::tls_client:
-    handle_ = ::SSL_CTX_new(::TLS_client_method());
-    if (handle_)
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-    break;
-  case context::tls_server:
-    handle_ = ::SSL_CTX_new(::TLS_server_method());
-    if (handle_)
-      SSL_CTX_set_min_proto_version(handle_, TLS1_VERSION);
-    break;
-#else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
-  case context::tls:
-    handle_ = ::SSL_CTX_new(::SSLv23_method());
-    if (handle_)
-      SSL_CTX_set_options(handle_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
-    break;
-  case context::tls_client:
-    handle_ = ::SSL_CTX_new(::SSLv23_client_method());
-    if (handle_)
-      SSL_CTX_set_options(handle_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
-    break;
-  case context::tls_server:
-    handle_ = ::SSL_CTX_new(::SSLv23_server_method());
-    if (handle_)
-      SSL_CTX_set_options(handle_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
-    break;
-#endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
-
+#if defined(OPENSSL_NO_DTLS1_METHOD) \
+  || (OPENSSL_VERSION_NUMBER >= 0x10100000L)
+    case dtlsv1:
+    case dtlsv1_client:
+    case dtlsv1_server:
+      asio::detail::throw_error(
+          asio::error::invalid_argument, "context");
+      break;
+#else
+  case dtlsv1:
+    handle_ = ::SSL_CTX_new(::DTLSv1_method());
+    break;
+  case dtlsv1_client:
+    handle_ = ::SSL_CTX_new(::DTLSv1_client_method());
+    break;
+  case dtlsv1_server:
+    handle_ = ::SSL_CTX_new(::DTLSv1_server_method());
+    break;
+#endif
+
+#if defined(OPENSSL_NO_DTLS1_2_METHOD) \
+  ||  (OPENSSL_VERSION_NUMBER >= 0x10100000L) \
+  ||  (OPENSSL_VERSION_NUMBER <  0x10002001L)
+  case dtlsv12:
+  case dtlsv12_client:
+  case dtlsv12_server:
+      asio::detail::throw_error(
+          asio::error::invalid_argument, "context");
+    break;
+#else
+  case dtlsv12:
+    handle_ = ::SSL_CTX_new(::DTLSv1_2_method());
+    break;
+  case dtlsv12_client:
+    handle_ = ::SSL_CTX_new(::DTLSv1_2_client_method());
+    break;
+  case dtlsv12_server:
+    handle_ = ::SSL_CTX_new(::DTLSv1_2_server_method());
+    break;
+#endif // OPENSSL_NO_DTLS1_2_METHOD
+
+  case dtls:
+    handle_ = ::SSL_CTX_new(::DTLS_method());
+    break;
+  case dtls_client:
+    handle_ = ::SSL_CTX_new(::DTLS_client_method());
+    break;
+  case dtls_server:
+    handle_ = ::SSL_CTX_new(::DTLS_server_method());
+    break;
   default:
     handle_ = ::SSL_CTX_new(0);
     break;
@@ -341,18 +153,18 @@
 {
   if (handle_)
   {
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
     void* cb_userdata = ::SSL_CTX_get_default_passwd_cb_userdata(handle_);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
     void* cb_userdata = handle_->default_passwd_callback_userdata;
 #endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
     if (cb_userdata)
     {
-      detail::password_callback_base* callback =
-        static_cast<detail::password_callback_base*>(
+      ssl::detail::password_callback_base* callback =
+        static_cast<ssl::detail::password_callback_base*>(
             cb_userdata);
       delete callback;
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
       ::SSL_CTX_set_default_passwd_cb_userdata(handle_, 0);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
       handle_->default_passwd_callback_userdata = 0;
@@ -361,8 +173,8 @@
 
     if (SSL_CTX_get_app_data(handle_))
     {
-      detail::verify_callback_base* callback =
-        static_cast<detail::verify_callback_base*>(
+      ssl::detail::verify_callback_base* callback =
+        static_cast<ssl::detail::verify_callback_base*>(
             SSL_CTX_get_app_data(handle_));
       delete callback;
       SSL_CTX_set_app_data(handle_, 0);
@@ -686,7 +498,7 @@
   bio_cleanup bio = { make_buffer_bio(chain) };
   if (bio.p)
   {
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
     pem_password_cb* callback = ::SSL_CTX_get_default_passwd_cb(handle_);
     void* cb_userdata = ::SSL_CTX_get_default_passwd_cb_userdata(handle_);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
@@ -790,7 +602,7 @@
 {
   ::ERR_clear_error();
 
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
     pem_password_cb* callback = ::SSL_CTX_get_default_passwd_cb(handle_);
     void* cb_userdata = ::SSL_CTX_get_default_passwd_cb_userdata(handle_);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
@@ -857,7 +669,7 @@
 {
   ::ERR_clear_error();
 
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
     pem_password_cb* callback = ::SSL_CTX_get_default_passwd_cb(handle_);
     void* cb_userdata = ::SSL_CTX_get_default_passwd_cb_userdata(handle_);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
@@ -1049,11 +861,11 @@
 }
 
 ASIO_SYNC_OP_VOID context::do_set_verify_callback(
-    detail::verify_callback_base* callback, asio::error_code& ec)
+    ssl::detail::verify_callback_base* callback, asio::error_code& ec)
 {
   if (SSL_CTX_get_app_data(handle_))
   {
-    delete static_cast<detail::verify_callback_base*>(
+    delete static_cast<ssl::detail::verify_callback_base*>(
         SSL_CTX_get_app_data(handle_));
   }
 
@@ -1079,8 +891,8 @@
       {
         if (SSL_CTX_get_app_data(handle))
         {
-          detail::verify_callback_base* callback =
-            static_cast<detail::verify_callback_base*>(
+          ssl::detail::verify_callback_base* callback =
+            static_cast<ssl::detail::verify_callback_base*>(
                 SSL_CTX_get_app_data(handle));
 
           verify_context verify_ctx(ctx);
@@ -1094,9 +906,9 @@
 }
 
 ASIO_SYNC_OP_VOID context::do_set_password_callback(
-    detail::password_callback_base* callback, asio::error_code& ec)
-{
-#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
+    ssl::detail::password_callback_base* callback, asio::error_code& ec)
+{
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
   void* old_callback = ::SSL_CTX_get_default_passwd_cb_userdata(handle_);
   ::SSL_CTX_set_default_passwd_cb_userdata(handle_, callback);
 #else // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
@@ -1105,7 +917,7 @@
 #endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L)
 
   if (old_callback)
-    delete static_cast<detail::password_callback_base*>(
+    delete static_cast<ssl::detail::password_callback_base*>(
         old_callback);
 
   SSL_CTX_set_default_passwd_cb(handle_, &context::password_callback_function);
@@ -1121,8 +933,8 @@
 
   if (data)
   {
-    detail::password_callback_base* callback =
-      static_cast<detail::password_callback_base*>(data);
+    ssl::detail::password_callback_base* callback =
+      static_cast<ssl::detail::password_callback_base*>(data);
 
     std::string passwd = callback->call(static_cast<std::size_t>(size),
         purpose ? context_base::for_writing : context_base::for_reading);
