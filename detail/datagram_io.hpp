--- /usr/include/asio/ssl/detail/io.hpp
+++ /include/asio/ssl/dtls/detail/datagram_io.hpp
@@ -17,19 +17,25 @@
 
 #include "asio/detail/config.hpp"
 
-#include "asio/ssl/detail/engine.hpp"
-#include "asio/ssl/detail/stream_core.hpp"
+#include "asio/ssl/dtls/detail/engine.hpp"
+#include "asio/ssl/dtls/detail/core.hpp"
 #include "asio/write.hpp"
+#include "asio/socket_base.hpp"
 
 #include "asio/detail/push_options.hpp"
 
 namespace asio {
 namespace ssl {
+namespace dtls {
 namespace detail {
 
-template <typename Stream, typename Operation>
-std::size_t io(Stream& next_layer, stream_core& core,
-    const Operation& op, asio::error_code& ec)
+template <typename ReceiveFunction, typename SendFunction, typename Operation>
+std::size_t datagram_io(
+    const ReceiveFunction& receive,
+    const SendFunction& send,
+    core& core,
+    const Operation& op,
+    asio::error_code& ec)
 {
   std::size_t bytes_transferred = 0;
   do switch (op(core.engine_, ec, bytes_transferred))
@@ -40,7 +46,7 @@
     // the underlying transport.
     if (core.input_.size() == 0)
       core.input_ = asio::buffer(core.input_buffer_,
-          next_layer.read_some(core.input_buffer_, ec));
+          receive(core.input_buffer_, ec));
 
     // Pass the new input data to the engine.
     core.input_ = core.engine_.put_input(core.input_);
@@ -52,8 +58,7 @@
 
     // Get output data from the engine and write it to the underlying
     // transport.
-    asio::write(next_layer,
-        core.engine_.get_output(core.output_buffer_), ec);
+    send(core.engine_.get_output(core.output_buffer_), ec);
 
     // Try the operation again.
     continue;
@@ -62,8 +67,7 @@
 
     // Get output data from the engine and write it to the underlying
     // transport.
-    asio::write(next_layer,
-        core.engine_.get_output(core.output_buffer_), ec);
+    send(core.engine_.get_output(core.output_buffer_), ec);
 
     // Operation is complete. Return result to caller.
     core.engine_.map_error_code(ec);
@@ -82,13 +86,18 @@
   return 0;
 }
 
-template <typename Stream, typename Operation, typename Handler>
-class io_op
+template <typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
+class datagram_io_op
 {
 public:
-  io_op(Stream& next_layer, stream_core& core,
+  datagram_io_op(
+      const ReceiveFunction& receive,
+      const SendFunction& send,
+      core& core,
       const Operation& op, Handler& handler)
-    : next_layer_(next_layer),
+    : receive_function_(receive),
+      send_function_(send),
       core_(core),
       op_(op),
       start_(0),
@@ -99,8 +108,9 @@
   }
 
 #if defined(ASIO_HAS_MOVE)
-  io_op(const io_op& other)
-    : next_layer_(other.next_layer_),
+  datagram_io_op(const datagram_io_op& other)
+    : receive_function_(other.receive_function_),
+      send_function_(other.send_function_),
       core_(other.core_),
       op_(other.op_),
       start_(other.start_),
@@ -111,8 +121,9 @@
   {
   }
 
-  io_op(io_op&& other)
-    : next_layer_(other.next_layer_),
+  datagram_io_op(datagram_io_op&& other)
+    : receive_function_(other.receive_function_),
+      send_function_(other.send_function_),
       core_(other.core_),
       op_(other.op_),
       start_(other.start_),
@@ -154,14 +165,14 @@
             core_.pending_read_.expires_at(core_.pos_infin());
 
             // Start reading some data from the underlying transport.
-            next_layer_.async_read_some(
+            receive_function_(
                 asio::buffer(core_.input_buffer_),
-                ASIO_MOVE_CAST(io_op)(*this));
+                ASIO_MOVE_CAST(datagram_io_op)(*this));
           }
           else
           {
             // Wait until the current read operation completes.
-            core_.pending_read_.async_wait(ASIO_MOVE_CAST(io_op)(*this));
+            core_.pending_read_.async_wait(ASIO_MOVE_CAST(datagram_io_op)(*this));
           }
 
           // Yield control until asynchronous operation completes. Control
@@ -181,14 +192,13 @@
             core_.pending_write_.expires_at(core_.pos_infin());
 
             // Start writing all the data to the underlying transport.
-            asio::async_write(next_layer_,
-                core_.engine_.get_output(core_.output_buffer_),
-                ASIO_MOVE_CAST(io_op)(*this));
+            send_function_(core_.engine_.get_output(core_.output_buffer_),
+                                   ASIO_MOVE_CAST(datagram_io_op)(*this));
           }
           else
           {
             // Wait until the current write operation completes.
-            core_.pending_write_.async_wait(ASIO_MOVE_CAST(io_op)(*this));
+            core_.pending_write_.async_wait(ASIO_MOVE_CAST(datagram_io_op)(*this));
           }
 
           // Yield control until asynchronous operation completes. Control
@@ -204,9 +214,9 @@
           // read so the handler runs "as-if" posted using io_context::post().
           if (start)
           {
-            next_layer_.async_read_some(
+            receive_function_(
                 asio::buffer(core_.input_buffer_, 0),
-                ASIO_MOVE_CAST(io_op)(*this));
+                ASIO_MOVE_CAST(datagram_io_op)(*this));
 
             // Yield control until asynchronous operation completes. Control
             // resumes at the "default:" label below.
@@ -273,8 +283,9 @@
   }
 
 //private:
-  Stream& next_layer_;
-  stream_core& core_;
+  ReceiveFunction receive_function_;
+  SendFunction send_function_;
+  core& core_;
   Operation op_;
   int start_;
   engine::want want_;
@@ -283,82 +294,87 @@
   Handler handler_;
 };
 
-template <typename Stream, typename Operation, typename Handler>
+template <typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
 inline void* asio_handler_allocate(std::size_t size,
-    io_op<Stream, Operation, Handler>* this_handler)
+    datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>* this_handler)
 {
   return asio_handler_alloc_helpers::allocate(
       size, this_handler->handler_);
 }
 
-template <typename Stream, typename Operation, typename Handler>
+template <typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
 inline void asio_handler_deallocate(void* pointer, std::size_t size,
-    io_op<Stream, Operation, Handler>* this_handler)
+    datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>* this_handler)
 {
   asio_handler_alloc_helpers::deallocate(
       pointer, size, this_handler->handler_);
 }
 
-template <typename Stream, typename Operation, typename Handler>
+template <typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
 inline bool asio_handler_is_continuation(
-    io_op<Stream, Operation, Handler>* this_handler)
+    datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>* this_handler)
 {
   return this_handler->start_ == 0 ? true
     : asio_handler_cont_helpers::is_continuation(this_handler->handler_);
 }
 
-template <typename Function, typename Stream,
-    typename Operation, typename Handler>
+template <typename Function, typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
 inline void asio_handler_invoke(Function& function,
-    io_op<Stream, Operation, Handler>* this_handler)
+    datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>* this_handler)
 {
   asio_handler_invoke_helpers::invoke(
       function, this_handler->handler_);
 }
 
-template <typename Function, typename Stream,
-    typename Operation, typename Handler>
+template <typename Function, typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
 inline void asio_handler_invoke(const Function& function,
-    io_op<Stream, Operation, Handler>* this_handler)
+    datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>* this_handler)
 {
   asio_handler_invoke_helpers::invoke(
       function, this_handler->handler_);
 }
 
-template <typename Stream, typename Operation, typename Handler>
-inline void async_io(Stream& next_layer, stream_core& core,
-    const Operation& op, Handler& handler)
-{
-  io_op<Stream, Operation, Handler>(
-    next_layer, core, op, handler)(
+template <typename ReceiveFunction, typename SendFunction,
+          typename Operation, typename Handler>
+inline void async_datagram_io(const ReceiveFunction& rf, const SendFunction& sf,
+    core& core, const Operation& op, Handler& handler)
+{
+  datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>(
+    rf, sf, core, op, handler)(
       asio::error_code(), 0, 1);
 }
 
 } // namespace detail
+} // namespace dtls
 } // namespace ssl
 
-template <typename Stream, typename Operation,
+template <typename ReceiveFunction, typename SendFunction, typename Operation,
     typename Handler, typename Allocator>
 struct associated_allocator<
-    ssl::detail::io_op<Stream, Operation, Handler>, Allocator>
+    ssl::dtls::detail::datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>, Allocator>
 {
   typedef typename associated_allocator<Handler, Allocator>::type type;
 
-  static type get(const ssl::detail::io_op<Stream, Operation, Handler>& h,
+  static type get(const ssl::dtls::detail::datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>& h,
       const Allocator& a = Allocator()) ASIO_NOEXCEPT
   {
     return associated_allocator<Handler, Allocator>::get(h.handler_, a);
   }
 };
 
-template <typename Stream, typename Operation,
+template <typename ReceiveFunction, typename SendFunction, typename Operation,
     typename Handler, typename Executor>
 struct associated_executor<
-    ssl::detail::io_op<Stream, Operation, Handler>, Executor>
+    ssl::dtls::detail::datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>, Executor>
 {
   typedef typename associated_executor<Handler, Executor>::type type;
 
-  static type get(const ssl::detail::io_op<Stream, Operation, Handler>& h,
+  static type get(const ssl::dtls::detail::datagram_io_op<ReceiveFunction, SendFunction, Operation, Handler>& h,
       const Executor& ex = Executor()) ASIO_NOEXCEPT
   {
     return associated_executor<Handler, Executor>::get(h.handler_, ex);
