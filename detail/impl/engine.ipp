--- /usr/include/asio/ssl/detail/impl/engine.ipp
+++ /include/asio/ssl/dtls/detail/impl/engine.ipp
@@ -8,8 +8,8 @@
 // file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
 //
 
-#ifndef ASIO_SSL_DETAIL_IMPL_ENGINE_IPP
-#define ASIO_SSL_DETAIL_IMPL_ENGINE_IPP
+#ifndef ASIO_SSL_DTLS_DETAIL_IMPL_ENGINE_IPP
+#define ASIO_SSL_DTLS_DETAIL_IMPL_ENGINE_IPP
 
 #if defined(_MSC_VER) && (_MSC_VER >= 1200)
 # pragma once
@@ -19,14 +19,19 @@
 
 #include "asio/detail/throw_error.hpp"
 #include "asio/error.hpp"
-#include "asio/ssl/detail/engine.hpp"
+#include "asio/ssl/dtls/detail/engine.hpp"
 #include "asio/ssl/error.hpp"
 #include "asio/ssl/verify_context.hpp"
+#include "asio/ssl/dtls/detail/ssl_app_data.hpp"
 
 #include "asio/detail/push_options.hpp"
+
+#include <openssl/opensslv.h>
+#include <openssl/bio.h>
 
 namespace asio {
 namespace ssl {
+namespace dtls {
 namespace detail {
 
 engine::engine(SSL_CTX* context)
@@ -53,13 +58,15 @@
   ::BIO* int_bio = 0;
   ::BIO_new_bio_pair(&int_bio, 0, &ext_bio_, 0);
   ::SSL_set_bio(ssl_, int_bio, int_bio);
+
+  SSL_set_app_data(ssl_, new ssl_app_data());
 }
 
 engine::~engine()
 {
   if (SSL_get_app_data(ssl_))
   {
-    delete static_cast<verify_callback_base*>(SSL_get_app_data(ssl_));
+    delete static_cast<detail::ssl_app_data*>(SSL_get_app_data(ssl_));
     SSL_set_app_data(ssl_, 0);
   }
 
@@ -72,6 +79,108 @@
   return ssl_;
 }
 
+bool engine::set_mtu(int mtu)
+{
+  SSL_set_options(ssl_, SSL_OP_NO_QUERY_MTU);
+
+  long mtu_val = mtu;
+  return (::SSL_set_mtu(ssl_, mtu) == mtu_val);
+}
+
+void engine::set_dtls_tmp_data(void* data)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl_));
+
+  appdata->set_dtls_tmp(data);
+}
+
+void* engine::get_dtls_tmp_data()
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl_));
+
+  return appdata->getDTLSTmp();
+}
+
+asio::error_code engine::set_cookie_generate_callback(
+  dtls::detail::cookie_generate_callback_base* callback,
+  asio::error_code& ec)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl_));
+
+  appdata->setCookieGenerateCallback(callback);
+
+  SSL_CTX* ctx = ::SSL_get_SSL_CTX(ssl_);
+
+  ::SSL_CTX_set_cookie_generate_cb(
+        ctx, &engine::generate_cookie_function);
+
+  ec = asio::error_code();
+  return ec;
+}
+
+int engine::generate_cookie_function(
+    SSL *ssl, unsigned char *cookie, unsigned int *length)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl));
+
+  dtls::detail::cookie_generate_callback_base* cb
+    = appdata->getCookieGenerateCallback();
+
+  std::string cookie_str;
+  cb->call(cookie_str, appdata->getDTLSTmp());
+
+  if(cookie_str.length() >= DTLS1_COOKIE_LENGTH)
+  {
+    cookie_str = cookie_str.substr(0, DTLS1_COOKIE_LENGTH-1);
+  }
+
+  std::copy(cookie_str.begin(), cookie_str.end(), cookie);
+  *length = static_cast<unsigned int>(cookie_str.length());
+
+  return 1;
+}
+
+asio::error_code engine::set_cookie_verify_callback(
+  dtls::detail::cookie_verify_callback_base* callback,
+  asio::error_code& ec)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl_));
+
+  appdata->setCookieVerifyCallback(callback);
+
+  SSL_CTX* ctx = ::SSL_get_SSL_CTX(ssl_);
+
+  ::SSL_CTX_set_cookie_verify_cb(ctx, &engine::verify_cookie_function);
+
+  ec = asio::error_code();
+  return ec;
+}
+
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
+int engine::verify_cookie_function(
+      SSL *ssl, const unsigned char *cookie, unsigned int length)
+#else  //(OPENSSL_VERSION_NUMBER >= 0x10100000L)
+int engine::verify_cookie_function(
+      SSL *ssl, unsigned char *cookie, unsigned int length)
+#endif //(OPENSSL_VERSION_NUMBER >= 0x10100000L)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl));
+
+  dtls::detail::cookie_verify_callback_base* cb
+    = appdata->getCookieVerifyCallback();
+
+  std::string cookie_str((const char *)cookie, length);
+
+  if (cb->call(cookie_str, appdata->getDTLSTmp()))
+  {
+    return 1;
+  }
+  else
+  {
+    return 0;
+  }
+}
+
 asio::error_code engine::set_verify_mode(
     verify_mode v, asio::error_code& ec)
 {
@@ -91,12 +200,11 @@
 }
 
 asio::error_code engine::set_verify_callback(
-    verify_callback_base* callback, asio::error_code& ec)
-{
-  if (SSL_get_app_data(ssl_))
-    delete static_cast<verify_callback_base*>(SSL_get_app_data(ssl_));
-
-  SSL_set_app_data(ssl_, callback);
+    ssl::detail::verify_callback_base* callback, asio::error_code& ec)
+{
+  ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl_));
+
+  appdata->setVerifyCallback(callback);
 
   ::SSL_set_verify(ssl_, ::SSL_get_verify_mode(ssl_),
       &engine::verify_callback_function);
@@ -113,12 +221,10 @@
           ::X509_STORE_CTX_get_ex_data(
             ctx, ::SSL_get_ex_data_X509_STORE_CTX_idx())))
     {
-      if (SSL_get_app_data(ssl))
+      ssl_app_data* appdata = static_cast<ssl_app_data*>(SSL_get_app_data(ssl));
+      ssl::detail::verify_callback_base *callback = appdata->getVerifyCallback();
+      if (callback)
       {
-        verify_callback_base* callback =
-          static_cast<verify_callback_base*>(
-              SSL_get_app_data(ssl));
-
         verify_context verify_ctx(ctx);
         return callback->call(preverified != 0, verify_ctx) ? 1 : 0;
       }
@@ -126,6 +232,11 @@
   }
 
   return 0;
+}
+
+engine::want engine::dtls_listen(asio::error_code& ec)
+{
+  return perform(&engine::do_dtls_listen, 0, 0, ec, 0);
 }
 
 engine::want engine::handshake(
@@ -243,7 +354,7 @@
     return want_nothing;
   }
 
-  if (ssl_error == SSL_ERROR_SYSCALL)
+  if ((ssl_error == SSL_ERROR_SYSCALL) && (sys_error != 0))
   {
     ec = asio::error_code(sys_error,
         asio::error::get_system_category());
@@ -278,6 +389,45 @@
     ec = asio::error_code();
     return want_nothing;
   }
+}
+
+int engine::do_dtls_listen(void* data, std::size_t length)
+{
+#if (OPENSSL_VERSION_NUMBER >= 0x1010003fL)
+  (void)data;
+  (void)length;
+
+  BIO_ADDR *addr = BIO_ADDR_new();
+  int result = DTLSv1_listen(ssl_, addr);
+  BIO_ADDR_free(addr);
+
+  // Remove data from BIO -> be consistent with old version
+  BIO_reset(ext_bio_);
+
+  return result;
+#elif (OPENSSL_VERSION_NUMBER >= 0x0009080fL)
+  /* This is a workaround for DTLSv1_listen incompatibility with
+   * memory BIOs. It essentialy contains the same code as DTLSv1_listen
+   * but does not copy the peer's address.
+   */
+
+  /* Ensure there is no state left over from a previous invocation */
+  SSL_clear(ssl_);
+
+  ::SSL_set_options(ssl_, SSL_OP_COOKIE_EXCHANGE);
+  ssl_->d1->listen = 1;
+
+  int result = do_accept(data, length);
+
+  ssl_->d1->listen = 0;
+
+  return result;
+#else
+  thow asio::detail::throw_error(
+        asio::error::operation_not_supported, "engine"
+        );
+#endif // (OPENSSL_VERSION_NUMBER < 0x10100003)
+
 }
 
 int engine::do_accept(void*, std::size_t)

