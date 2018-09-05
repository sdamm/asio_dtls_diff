--- /usr/include/asio/ssl/detail/buffered_handshake_op.hpp
+++ /include/asio/ssl/dtls/detail/buffered_dtls_listen_op.hpp
 #if defined(_MSC_VER) && (_MSC_VER >= 1200)
 # pragma once
@@ -17,33 +17,45 @@
 
 #include "asio/detail/config.hpp"
 
-#include "asio/ssl/detail/engine.hpp"
+#include "asio/ssl/dtls/detail/engine.hpp"
 
 #include "asio/detail/push_options.hpp"
 
 namespace asio {
 namespace ssl {
+namespace dtls {
 namespace detail {
 
-template <typename ConstBufferSequence>
-class buffered_handshake_op
+template <typename ConstBuffer>
+class buffered_dtls_listen_op
 {
 public:
-  buffered_handshake_op(stream_base::handshake_type type,
-      const ConstBufferSequence& buffers)
-    : type_(type),
-      buffers_(buffers),
-      total_buffer_size_(asio::buffer_size(buffers_))
+  buffered_dtls_listen_op(const ConstBuffer& buffers)
+    : buffer_(buffers)
   {
   }
 
-  engine::want operator()(engine& eng,
+  ssl::dtls::detail::engine::want operator()(dtls::detail::engine& eng,
       asio::error_code& ec,
       std::size_t& bytes_transferred) const
   {
-    return this->process(eng, ec, bytes_transferred,
-        asio::buffer_sequence_begin(buffers_),
-        asio::buffer_sequence_end(buffers_));
+    eng.put_input(buffer_);
+    bytes_transferred = asio::buffer_size(buffer_);
+    ssl::dtls::detail::engine::want result = eng.dtls_listen(ec);
+
+    // Don't retry -> call again to retry
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
 
   template <typename Handler>
@@ -55,60 +67,14 @@
   }
 
 private:
-  template <typename Iterator>
-  engine::want process(engine& eng,
-      asio::error_code& ec,
-      std::size_t& bytes_transferred,
-      Iterator begin, Iterator end) const
-  {
-    Iterator iter = begin;
-    std::size_t accumulated_size = 0;
-
-    for (;;)
-    {
-      engine::want want = eng.handshake(type_, ec);
-      if (want != engine::want_input_and_retry
-          || bytes_transferred == total_buffer_size_)
-        return want;
-
-      // Find the next buffer piece to be fed to the engine.
-      while (iter != end)
-      {
-        const_buffer buffer(*iter);
-
-        // Skip over any buffers which have already been consumed by the engine.
-        if (bytes_transferred >= accumulated_size + buffer.size())
-        {
-          accumulated_size += buffer.size();
-          ++iter;
-          continue;
-        }
-
-        // The current buffer may have been partially consumed by the engine on
-        // a previous iteration. If so, adjust the buffer to point to the
-        // unused portion.
-        if (bytes_transferred > accumulated_size)
-          buffer = buffer + (bytes_transferred - accumulated_size);
-
-        // Pass the buffer to the engine, and update the bytes transferred to
-        // reflect the total number of bytes consumed so far.
-        bytes_transferred += buffer.size();
-        buffer = eng.put_input(buffer);
-        bytes_transferred -= buffer.size();
-        break;
-      }
-    }
-  }
-
-  stream_base::handshake_type type_;
-  ConstBufferSequence buffers_;
-  std::size_t total_buffer_size_;
+  ConstBuffer buffer_;
 };
