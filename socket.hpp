--- /usr/include/asio/ssl/stream.hpp
+++ /include/asio/ssl/dtls/socket.hpp
+/// Provides Datagram-oriented functionality using SSL.
 /**
- * The stream class template provides asynchronous and blocking stream-oriented
+ * The dtls class template provides asynchronous and blocking stream-oriented
  * functionality using SSL.
  *
  * @par Thread Safety
@@ -49,18 +58,15 @@
  * strand.
  *
  * @par Example
- * To use the SSL stream template with an ip::tcp::socket, you would write:
+ * To use the SSL dtls template with an ip::udp::socket, you would write:
  * @code
  * asio::io_context io_context;
- * asio::ssl::context ctx(asio::ssl::context::sslv23);
- * asio::ssl::stream<asio:ip::tcp::socket> sock(io_context, ctx);
+ * asio::ssl::context ctx(asio::ssl::context::dtlsv12);
+ * asio::ssl::stream<asio:ip::udp::socket> sock(io_context, ctx);
  * @endcode
- *
- * @par Concepts:
- * AsyncReadStream, AsyncWriteStream, Stream, SyncReadStream, SyncWriteStream.
  */
-template <typename Stream>
-class stream :
+template <typename datagram_socket>
+class socket :
   public stream_base,
   private noncopyable
 {
@@ -68,14 +74,8 @@
   /// The native handle type of the SSL stream.
   typedef SSL* native_handle_type;
 
-  /// Structure for use with deprecated impl_type.
-  struct impl_struct
-  {
-    SSL* ssl;
-  };
-
   /// The type of the next layer.
-  typedef typename remove_reference<Stream>::type next_layer_type;
+  typedef typename remove_reference<datagram_socket>::type next_layer_type;
 
   /// The type of the lowest layer.
   typedef typename next_layer_type::lowest_layer_type lowest_layer_type;
@@ -86,36 +86,43 @@
 #if defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
   /// Construct a stream.
   /**
-   * This constructor creates a stream and initialises the underlying stream
-   * object.
-   *
-   * @param arg The argument to be passed to initialise the underlying stream.
+   * This constructor creates a SSL object and initialises the underlying
+   * transport object.
+   *
+   * @param arg The argument to be passed to initialise the underlying
+   * transport.
    *
    * @param ctx The SSL context to be used for the stream.
    */
   template <typename Arg>
-  stream(Arg&& arg, context& ctx)
+  socket(Arg&& arg, context& ctx)
     : next_layer_(ASIO_MOVE_CAST(Arg)(arg)),
       core_(ctx.native_handle(),
           next_layer_.lowest_layer().get_executor().context())
   {
+    // set mtu to safe value to prevent dtls-fragmentation of the handshake
+    set_mtu(1500);
+    core_.engine_.set_dtls_tmp_data(&remote_endpoint_tmp_);
   }
 #else // defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
   template <typename Arg>
-  stream(Arg& arg, context& ctx)
+  socket(Arg& arg, context& ctx)
     : next_layer_(arg),
       core_(ctx.native_handle(),
           next_layer_.lowest_layer().get_executor().context())
   {
+    // set mtu to safe value to prevent dtls-fragmentation of the handshake
+    set_mtu(1500);
+    core_.engine_.set_dtls_tmp_data(&remote_endpoint_tmp_);
   }
 #endif // defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
 
   /// Destructor.
   /**
-   * @note A @c stream object must not be destroyed while there are pending
+   * @note A @c dtls object must not be destroyed while there are pending
    * asynchronous operations associated with it.
    */
-  ~stream()
+  ~socket()
   {
   }
 
@@ -228,6 +235,201 @@
     return next_layer_.lowest_layer();
   }
 
+  /// Set the MTU for the DTLS handshake
+  /**
+   * This function sets the MTU used for the Handshake.
+   *
+   * @param mtu the mtu to be set
+   *
+   * @param ec Set to indicate what error occurred, if any.
+   *
+   * @note Calls @c SSL_set_mtu
+   */
+  void set_mtu(int mtu, asio::error_code &ec)
+  {
+    if (core_.engine_.set_mtu(mtu))
+    {
+      ec = asio::error_code();
+    }
+    else
+    {
+      ec = asio::error_code(asio::error::invalid_argument,
+                            asio::error::system_category);
+    }
+  }
+
+  /// Set the MTU for the DTLS handshake
+  /**
+   * This function sets the MTU used for the Handshake.
+   *
+   * @param mtu the mtu to be set
+   *
+   * @throws asio::system_error Thrown on failure.
+   *
+   * @note Calls @c SSL_set_mtu
+   * Be aware that setting a small MTU will lead to fragmentation on the
+   * dtls layer which conflicts with the stateless cookie exchange.
+   */
+  void set_mtu(int mtu)
+  {
+    asio::error_code ec;
+    set_mtu(mtu, ec);
+    asio::detail::throw_error(ec, "set_mtu");
+  }
+
+  /// Set the callback used to generate dtls cookies
+  /**
+   * This function is used to specify a callback function that will be called
+   * by the implementation when it needs to generate a dtls cookie.
+   *
+   * @param callback The function object to be used for generating a cookie.
+   * The function signature of the handler must be:
+   * @code bool generate_callback(
+   *   asio::const_buffer & // A buffer containing a cookie
+   * ); @endcode
+   *
+   * @throws asio::system_error Thrown on failure.
+   *
+   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
+   */
+  template <typename CookieGenerateCallback>
+  ASIO_DECL void set_cookie_generate_callback(CookieGenerateCallback cb)
+  {
+    asio::error_code ec;
+    set_cookie_generate_callback(cb, ec);
+
+    asio::detail::throw_error(ec, "set_cookie_generate_callback");
+  }  
+
+  ASIO_DECL asio::error_code set_cookie_generate_callback(
+      detail::cookie_generate_callback_base& cb, asio::error_code& ec)
+  {
+    core_.engine_.set_cookie_generate_callback(cb.clone(), ec);
+
+    return ec;
+  }
+
+  /// Set the callback used to generate dtls cookies
+  /**
+   * This function is used to specify a callback function that will be called
+   * by the implementation when it needs to generate a dtls cookie.
+   *
+   * @param callback The function object to be used for generating a cookie.
+   * The function signature of the handler must be:
+   * @code bool generate_callback(
+   *   asio::const_buffer &cookie // Out parameter A buffer containing a cookie
+   * ); @endcode
+   *
+   * @param ec Set to indicate what error occurred, if any.
+   *
+   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
+   */
+  template <typename CookieVerifyCallback>
+  ASIO_DECL asio::error_code set_cookie_generate_callback(
+      CookieVerifyCallback callback, asio::error_code &ec)
+  {
+    core_.engine_.set_cookie_generate_callback(
+        new detail::cookie_generate_callback<
+          endpoint_type, CookieVerifyCallback>(callback),
+        ec
+      );
+
+    return ec;
+  }
+
+  ASIO_DECL asio::error_code set_cookie_verify_callback(
+      detail::cookie_verify_callback_base& callback, asio::error_code& ec)
+  {
+    core_.engine_.set_cookie_verify_callback(callback.clone(), ec);
+
+    return ec;
+  }
+
+  /// Set the callback used to verify dtls cookies
+  /**
+   * This function is used to specify a callback function that will be called
+   * by the implementation when it needs to verify a dtls cookie.
+   *
+   * @param callback The function object to be used for generating a cookie.
+   * The function signature of the handler must be:
+   * @code bool generate_callback(
+   *   asio::const_buffer & // A buffer containing a cookie
+   * ); @endcode
+   *
+   * @throws asio::system_error Thrown on failure.
+   *
+   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
+   */
+  template <typename CookieCallback>
+  ASIO_DECL void set_cookie_verify_callback(CookieCallback callback)
+  {
+    asio::error_code ec;
+    set_cookie_verify_callback(callback, ec);
+
+    asio::detail::throw_error(ec, "set_cookie_verify_callback");
+  }
+
+  /// Set the callback used to verify dtls cookies
+  /**
+   * This function is used to specify a callback function that will be called
+   * by the implementation when it needs to verify a dtls cookie.
+   *
+   * @param callback The function object to be used for generating a cookie.
+   * The function signature of the handler must be:
+   * @code bool generate_callback(
+   *   asio::const_buffer & // A buffer containing a cookie
+   * ); @endcode
+   *
+   * @param ec Set to indicate what error occurred, if any.
+   *
+   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
+   */
+  template <typename CookieCallback>
+  ASIO_DECL asio::error_code set_cookie_verify_callback(
+      CookieCallback callback, asio::error_code &ec)
+  {
+    core_.engine_.set_cookie_verify_callback(
+          new detail::cookie_verify_callback<endpoint_type, CookieCallback>(callback),
+          ec);
+
+    return ec;
+  }
+
+  /// Verify a DTLS cookie
+  /**
+   * This function verifies a received client cookie (DTLS client Hello).
+   * If the cookie does is not matched by the set cookie_verify function a
+   * HelloVerifyRequest is sent via the provided socket. This is a stateless
+   * version of the cookie exchange done by the handshake operation.
+   *
+   * To prevent the server side to work as amplifier for DOS attacks
+   * this function should be used to check the cookie before handshaking.
+   *
+   * @param socket the socket to sent the VerifyRequest with
+   *
+   * @param buffer data received on the listening socket
+   *
+   * @param ec Set to indicate what error occurred, if any.
+   *
+   * @param ep Remote endpoint for sending a HelloVerifyRequest to
+   *
+   * @return true if cookie did match, false otherwise
+   */
+  template <typename ConstBuffer>
+  bool verify_cookie(next_layer_type& socket, const ConstBuffer& buffer, asio::error_code &ec,
+                     typename next_layer_type::endpoint_type ep)
+  {
+    remote_endpoint_tmp_ = ep;
+
+    size_t result = ssl::dtls::detail::datagram_io(
+                      dtls::detail::datagram_receive<next_layer_type>(socket),
+                      dtls::detail::datagram_send_to<next_layer_type>(socket, ep),
+                      core_,
+                      detail::buffered_dtls_listen_op<ConstBuffer>(buffer), ec);
+
+    return (result != 0);
+  }
+
    * This function may be used to configure the peer verification mode used by
@@ -353,7 +555,7 @@
       asio::error_code& ec)
   {
     core_.engine_.set_verify_callback(
-        new detail::verify_callback<VerifyCallback>(callback), ec);
+        new ssl::detail::verify_callback<VerifyCallback>(callback), ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -387,7 +589,14 @@
   ASIO_SYNC_OP_VOID handshake(handshake_type type,
       asio::error_code& ec)
   {
-    detail::io(next_layer_, core_, detail::handshake_op(type), ec);
+    remote_endpoint_tmp_ = next_layer().remote_endpoint();
+
+    ssl::dtls::detail::datagram_io(
+          dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+          dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+          core_,
+          ssl::dtls::detail::handshake_op(type),
+          ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -427,8 +636,13 @@
   ASIO_SYNC_OP_VOID handshake(handshake_type type,
       const ConstBufferSequence& buffers, asio::error_code& ec)
   {
-    detail::io(next_layer_, core_,
-        detail::buffered_handshake_op<ConstBufferSequence>(type, buffers), ec);
+    remote_endpoint_tmp_ = next_layer().remote_endpoint();
+    ssl::dtls::detail::datagram_io(
+      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+      core_,
+      detail::buffered_handshake_op<ConstBufferSequence>(type, buffers),
+      ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -460,8 +674,13 @@
     asio::async_completion<HandshakeHandler,
       void (asio::error_code)> init(handler);
 
-    detail::async_io(next_layer_, core_,
-        detail::handshake_op(type), init.completion_handler);
+    remote_endpoint_tmp_ = next_layer().remote_endpoint();
+
+    ssl::dtls::detail::async_datagram_io(
+          dtls::detail::async_datagram_receive_timeout<next_layer_type>(next_layer_),
+          dtls::detail::async_datagram_send<next_layer_type>(next_layer_),
+          core_,
+          detail::handshake_op(type), init.completion_handler);
 
     return init.result.get();
   }
@@ -498,10 +717,15 @@
     ASIO_BUFFERED_HANDSHAKE_HANDLER_CHECK(
         BufferedHandshakeHandler, handler) type_check;
 
+    remote_endpoint_tmp_ = next_layer().remote_endpoint();
+
     asio::async_completion<BufferedHandshakeHandler,
       void (asio::error_code, std::size_t)> init(handler);
 
-    detail::async_io(next_layer_, core_,
+    ssl::dtls::detail::async_datagram_io(
+        dtls::detail::async_datagram_receive_timeout<next_layer_type>(next_layer_),
+        dtls::detail::async_datagram_send<next_layer_type>(next_layer_),
+        core_,
         detail::buffered_handshake_op<ConstBufferSequence>(type, buffers),
         init.completion_handler);
 
@@ -531,7 +755,11 @@
    */
   ASIO_SYNC_OP_VOID shutdown(asio::error_code& ec)
   {
-    detail::io(next_layer_, core_, detail::shutdown_op(), ec);
+    ssl::dtls::detail::datagram_io(
+      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+      core_, detail::shutdown_op(),
+      ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -559,59 +787,64 @@
     asio::async_completion<ShutdownHandler,
       void (asio::error_code)> init(handler);
 
-    detail::async_io(next_layer_, core_, detail::shutdown_op(),
-        init.completion_handler);
+    ssl::dtls::detail::async_datagram_io(
+      dtls::detail::async_datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::async_datagram_send<next_layer_type>(this->next_layer_, 0),
+      core_,
+      detail::shutdown_op(),
+      init.completion_handler);
 
     return init.result.get();
   }
 
-  /// Write some data to the stream.
-  /**
-   * This function is used to write data on the stream. The function call will
-   * block until one or more bytes of data has been written successfully, or
-   * until an error occurs.
-   *
-   * @param buffers The data to be written.
-   *
-   * @returns The number of bytes written.
+  /// Send data on the dtls connection.
+  /**
+   * This function is used to send data on the dtls connection. The function
+   * call will block until the data has been sent successfully
+   * or an error occurs.
+   *
+   * @param buffers The data to be written to the dtls connection.
+   *
+   * @returns The number of bytes written. Returns 0 if an error occurred.
    *
    * @throws asio::system_error Thrown on failure.
-   *
-   * @note The write_some operation may not transmit all of the data to the
-   * peer. Consider using the @ref write function if you need to ensure that all
-   * data is written before the blocking operation completes.
    */
   template <typename ConstBufferSequence>
-  std::size_t write_some(const ConstBufferSequence& buffers)
+  size_t send(ConstBufferSequence cb)
   {
     asio::error_code ec;
-    std::size_t n = write_some(buffers, ec);
-    asio::detail::throw_error(ec, "write_some");
-    return n;
-  }
-
-  /// Write some data to the stream.
-  /**
-   * This function is used to write data on the stream. The function call will
-   * block until one or more bytes of data has been written successfully, or
-   * until an error occurs.
-   *
-   * @param buffers The data to be written to the stream.
+    std::size_t res = ssl::dtls::detail::datagram_io(
+         dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+         dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+         this->core_,
+         detail::write_op<ConstBufferSequence>(cb),
+         ec);
+    asio::detail::throw_error(ec, "send");
+    return res;
+  }
+
+  /// Send data on the dtls connection.
+  /**
+   * This function is used to send data on the dtls connection. The function
+   * call will block until the data has been sent successfully
+   * or an error occurs.
+   *
+   * @param buffers The data to be written to the dtls connection.
    *
    * @param ec Set to indicate what error occurred, if any.
    *
    * @returns The number of bytes written. Returns 0 if an error occurred.
    *
-   * @note The write_some operation may not transmit all of the data to the
-   * peer. Consider using the @ref write function if you need to ensure that all
-   * data is written before the blocking operation completes.
    */
   template <typename ConstBufferSequence>
-  std::size_t write_some(const ConstBufferSequence& buffers,
-      asio::error_code& ec)
-  {
-    return detail::io(next_layer_, core_,
-        detail::write_op<ConstBufferSequence>(buffers), ec);
+  std::size_t send(ConstBufferSequence cb, asio::error_code &ec)
+  {
+    return ssl::dtls::detail::datagram_io(
+      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+      this->core_,
+      detail::write_op<ConstBufferSequence>(cb),
+      ec);
   }
 
   /// Start an asynchronous write.
@@ -639,8 +872,8 @@
   template <typename ConstBufferSequence, typename WriteHandler>
   ASIO_INITFN_RESULT_TYPE(WriteHandler,
       void (asio::error_code, std::size_t))
-  async_write_some(const ConstBufferSequence& buffers,
-      ASIO_MOVE_ARG(WriteHandler) handler)
+  async_send(const ConstBufferSequence& buffers,
+             ASIO_MOVE_ARG(WriteHandler) handler)
   {
     // If you get an error on the following line it means that your handler does
     // not meet the documented type requirements for a WriteHandler.
@@ -649,66 +882,78 @@
     asio::async_completion<WriteHandler,
       void (asio::error_code, std::size_t)> init(handler);
 
-    detail::async_io(next_layer_, core_,
+    ssl::dtls::detail::async_datagram_io(
+        detail::async_datagram_receive<next_layer_type>(next_layer_),
+        detail::async_datagram_send<next_layer_type>(next_layer_),
+        core_,
         detail::write_op<ConstBufferSequence>(buffers),
         init.completion_handler);
 
     return init.result.get();
   }
 
-  /// Read some data from the stream.
-  /**
-   * This function is used to read data from the stream. The function call will
-   * block until one or more bytes of data has been read successfully, or until
-   * an error occurs.
+  /// Receive some data from the socket.
+  /**
+   * This function is used to receive data on the dtls socket.
+   * The function call will block until data has been received
+   * successfully or an error occurs. 
    *
    * @param buffers The buffers into which the data will be read.
    *
-   * @returns The number of bytes read.
+   * @param ec Set to indicate what error occurred, if any.
+   *
+   * @returns The number of bytes read. Returns 0 if an error occurred.
+   */
+  template <typename BufferSequence>
+  std::size_t receive(BufferSequence mb)
+  {
+    asio::error_code ec;
+    std::size_t res = ssl::dtls::detail::datagram_io(
+      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+      this->core_,
+      detail::read_op<BufferSequence>(mb),
+      ec);
+
+    asio::detail::throw_error(ec, "receive");
+    return res;
+  }
+
+  /// Receive some data on a dtls connection.
+  /**
+   * This function is used to receive data on the dtls connection.
+   * The function call will block until data has been received successfully
+   * or an error occurs.
+   *
+   * @param buffers One or more buffers into which the data will be received.
+   *
+   * @returns The number of bytes received.
    *
    * @throws asio::system_error Thrown on failure.
    *
-   * @note The read_some operation may not read all of the requested number of
-   * bytes. Consider using the @ref read function if you need to ensure that the
-   * requested amount of data is read before the blocking operation completes.
-   */
-  template <typename MutableBufferSequence>
-  std::size_t read_some(const MutableBufferSequence& buffers)
-  {
-    asio::error_code ec;
-    std::size_t n = read_some(buffers, ec);
-    asio::detail::throw_error(ec, "read_some");
-    return n;
-  }
-
-  /// Read some data from the stream.
-  /**
-   * This function is used to read data from the stream. The function call will
-   * block until one or more bytes of data has been read successfully, or until
-   * an error occurs.
-   *
-   * @param buffers The buffers into which the data will be read.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @returns The number of bytes read. Returns 0 if an error occurred.
-   *
-   * @note The read_some operation may not read all of the requested number of
-   * bytes. Consider using the @ref read function if you need to ensure that the
-   * requested amount of data is read before the blocking operation completes.
-   */
-  template <typename MutableBufferSequence>
-  std::size_t read_some(const MutableBufferSequence& buffers,
-      asio::error_code& ec)
-  {
-    return detail::io(next_layer_, core_,
-        detail::read_op<MutableBufferSequence>(buffers), ec);
-  }
-
-  /// Start an asynchronous read.
-  /**
-   * This function is used to asynchronously read one or more bytes of data from
-   * the stream. The function call always returns immediately.
+   * @par Example
+   * To receive into a single data buffer use the @ref buffer function as
+   * follows:
+   * @code socket.receive(asio::buffer(data, size)); @endcode
+   * See the @ref buffer documentation for information on receiving into
+   * multiple buffers in one go, and how to use it with arrays, boost::array or
+   * std::vector.
+   */
+  template <typename BufferSequence>
+  std::size_t receive(BufferSequence mb, asio::error_code &ec)
+  {
+    return ssl::dtls::detail::datagram_io(
+      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
+      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
+      this->core_,
+      detail::read_op<BufferSequence>(mb),
+      ec);
+  }
+
+  /// Start an asynchronous receive.
+  /**
+   * This function is used to asynchronously receive data on
+   * the dtls socket. The function call always returns immediately.
    *
    * @param buffers The buffers into which the data will be read. Although the
    * buffers object may be copied as necessary, ownership of the underlying
@@ -722,16 +967,11 @@
    *   const asio::error_code& error, // Result of operation.
    *   std::size_t bytes_transferred           // Number of bytes read.
    * ); @endcode
-   *
-   * @note The async_read_some operation may not read all of the requested
-   * number of bytes. Consider using the @ref async_read function if you need to
-   * ensure that the requested amount of data is read before the asynchronous
-   * operation completes.
    */
   template <typename MutableBufferSequence, typename ReadHandler>
   ASIO_INITFN_RESULT_TYPE(ReadHandler,
       void (asio::error_code, std::size_t))
-  async_read_some(const MutableBufferSequence& buffers,
+  async_receive(const MutableBufferSequence& buffers,
       ASIO_MOVE_ARG(ReadHandler) handler)
   {
     // If you get an error on the following line it means that your handler does
@@ -741,21 +981,28 @@
     asio::async_completion<ReadHandler,
       void (asio::error_code, std::size_t)> init(handler);
 
-    detail::async_io(next_layer_, core_,
+    ssl::dtls::detail::async_datagram_io(
+        dtls::detail::async_datagram_receive<next_layer_type>(next_layer_),
+        dtls::detail::async_datagram_send<next_layer_type>(next_layer_, 0),
+        core_,
         detail::read_op<MutableBufferSequence>(buffers),
         init.completion_handler);
 
     return init.result.get();
   }
-
 private:
-  Stream next_layer_;
-  detail::stream_core core_;
+  typedef typename asio::remove_reference<
+    datagram_socket>::type::endpoint_type endpoint_type;
+
+  datagram_socket next_layer_;
+  ssl::dtls::detail::core core_;
+  endpoint_type remote_endpoint_tmp_;
 };

