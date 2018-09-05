--- /usr/include/asio/ssl/detail/verify_callback.hpp
+++ /include/asio/ssl/dtls/detail/cookie_generate_callback.hpp
 #if defined(_MSC_VER) && (_MSC_VER >= 1200)
 # pragma once
-class verify_callback_base
+class cookie_generate_callback_base
 {
 public:
-  virtual ~verify_callback_base()
+  virtual ~cookie_generate_callback_base()
   {
   }
 
-  virtual bool call(bool preverified, verify_context& ctx) = 0;
+  virtual bool call(std::string &cookie, void *data) = 0;
+
+  virtual cookie_generate_callback_base *clone() = 0;
 };
 
-template <typename VerifyCallback>
-class verify_callback : public verify_callback_base
+template <typename EndpointType, typename CookieGenerateCallback>
+class cookie_generate_callback : public cookie_generate_callback_base
 {
 public:
-  explicit verify_callback(VerifyCallback callback)
+  explicit cookie_generate_callback(CookieGenerateCallback callback)
     : callback_(callback)
   {
   }
 
-  virtual bool call(bool preverified, verify_context& ctx)
+  virtual bool call(std::string &cookie, void *data)
   {
-    return callback_(preverified, ctx);
+    EndpointType& ep = *static_cast<EndpointType*>(data);
+    return callback_(cookie, ep);
+  }
+
+  virtual cookie_generate_callback_base* clone()
+  {
+    return new
+      cookie_generate_callback<EndpointType, CookieGenerateCallback>(callback_);
   }
 
 private:
-  VerifyCallback callback_;
+  CookieGenerateCallback callback_;
 };
 
