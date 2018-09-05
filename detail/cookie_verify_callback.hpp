--- /usr/include/asio/ssl/detail/verify_callback.hpp
+++ /include/asio/ssl/dtls/detail/cookie_verify_callback.hpp
@@ -23,40 +23,51 @@
 
 namespace asio {
 namespace ssl {
+namespace dtls {
 namespace detail {
 
-class verify_callback_base
+class cookie_verify_callback_base
 {
 public:
-  virtual ~verify_callback_base()
+  virtual ~cookie_verify_callback_base()
   {
   }
 
-  virtual bool call(bool preverified, verify_context& ctx) = 0;
+  virtual bool call(std::string &cookie, void *data) = 0;
+
+  virtual cookie_verify_callback_base* clone() = 0;
 };
 
-template <typename VerifyCallback>
-class verify_callback : public verify_callback_base
+template <typename EndpointType, typename CookieVerifyCallback>
+class cookie_verify_callback : public cookie_verify_callback_base
 {
 public:
-  explicit verify_callback(VerifyCallback callback)
+  explicit cookie_verify_callback(CookieVerifyCallback callback)
     : callback_(callback)
   {
   }
 
-  virtual bool call(bool preverified, verify_context& ctx)
+  virtual bool call(std::string &cookie, void *data)
   {
-    return callback_(preverified, ctx);
+    EndpointType &ep = *static_cast<EndpointType *>(data);
+    return callback_(cookie, ep);
+  }
+
+  virtual cookie_verify_callback_base* clone()
+  {
+    return
+      new cookie_verify_callback<EndpointType, CookieVerifyCallback>(callback_);
   }
 
 private:
-  VerifyCallback callback_;
+  CookieVerifyCallback callback_;
 };
