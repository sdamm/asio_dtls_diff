--- /usr/include/asio/basic_socket_acceptor.hpp
+++ /include/asio/ssl/dtls/acceptor.hpp
@@ -1,331 +1,49 @@
-//
-// basic_socket_acceptor.hpp
-// ~~~~~~~~~~~~~~~~~~~~~~~~~
-//
-// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
-//
-// Distributed under the Boost Software License, Version 1.0. (See accompanying
-// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
-//
-
-#ifndef ASIO_BASIC_SOCKET_ACCEPTOR_HPP
-#define ASIO_BASIC_SOCKET_ACCEPTOR_HPP
-
-#if defined(_MSC_VER) && (_MSC_VER >= 1200)
-# pragma once
-#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)
-
-#include "asio/detail/config.hpp"
+#ifndef ASIO_DTLS_ACCEPTOR_HPP
+#define ASIO_DTLS_ACCEPTOR_HPP
+
+#include "asio/detail/push_options.hpp"
+
+#include "asio/io_service.hpp"
+#include "asio/basic_socket.hpp"
 #include "asio/basic_io_object.hpp"
-#include "asio/basic_socket.hpp"
-#include "asio/detail/handler_type_requirements.hpp"
-#include "asio/detail/throw_error.hpp"
-#include "asio/detail/type_traits.hpp"
-#include "asio/error.hpp"
-#include "asio/socket_base.hpp"
-
-#if defined(ASIO_HAS_MOVE)
-# include <utility>
-#endif // defined(ASIO_HAS_MOVE)
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-# include "asio/socket_acceptor_service.hpp"
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-# if defined(ASIO_WINDOWS_RUNTIME)
-#  include "asio/detail/null_socket_service.hpp"
-#  define ASIO_SVC_T detail::null_socket_service<Protocol>
-# elif defined(ASIO_HAS_IOCP)
-#  include "asio/detail/win_iocp_socket_service.hpp"
-#  define ASIO_SVC_T detail::win_iocp_socket_service<Protocol>
-# else
-#  include "asio/detail/reactive_socket_service.hpp"
-#  define ASIO_SVC_T detail::reactive_socket_service<Protocol>
-# endif
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-
-#include "asio/detail/push_options.hpp"
+#include "asio/ssl/dtls/socket.hpp"
+#include "asio/detail/memory.hpp"
+#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
+#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"
+#include "asio/ssl/error.hpp"
+#include "asio/error_code.hpp"
+#include "asio/ssl/dtls/context.hpp"
+#include "asio/executor_work_guard.hpp"
+
 
 namespace asio {
-
-/// Provides the ability to accept new connections.
-/**
- * The basic_socket_acceptor class template is used for accepting new socket
- * connections.
- *
- * @par Thread Safety
- * @e Distinct @e objects: Safe.@n
- * @e Shared @e objects: Unsafe.
- *
- * @par Example
- * Opening a socket acceptor with the SO_REUSEADDR option enabled:
- * @code
- * asio::ip::tcp::acceptor acceptor(io_context);
- * asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), port);
- * acceptor.open(endpoint.protocol());
- * acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
- * acceptor.bind(endpoint);
- * acceptor.listen();
- * @endcode
- */
-template <typename Protocol
-    ASIO_SVC_TPARAM_DEF1(= socket_acceptor_service<Protocol>)>
-class basic_socket_acceptor
-  : ASIO_SVC_ACCESS basic_io_object<ASIO_SVC_T>,
-    public socket_base
+namespace ssl {
+namespace dtls {
+
+template <typename DatagramSocketType>
+class acceptor;
+
+template <typename DatagramSocketType>
+class acceptor
 {
 public:
-  /// The type of the executor associated with the object.
-  typedef io_context::executor_type executor_type;
-
-  /// The native representation of an acceptor.
-#if defined(GENERATING_DOCUMENTATION)
-  typedef implementation_defined native_handle_type;
-#else
-  typedef typename ASIO_SVC_T::native_handle_type native_handle_type;
-#endif
-
-  /// The protocol type.
-  typedef Protocol protocol_type;
-
-  /// The endpoint type.
-  typedef typename Protocol::endpoint endpoint_type;
-
-  /// Construct an acceptor without opening it.
-  /**
-   * This constructor creates an acceptor without opening it to listen for new
-   * connections. The open() function must be called before the acceptor can
-   * accept new socket connections.
-   *
-   * @param io_context The io_context object that the acceptor will use to
-   * dispatch handlers for any asynchronous operations performed on the
-   * acceptor.
-   */
-  explicit basic_socket_acceptor(asio::io_context& io_context)
-    : basic_io_object<ASIO_SVC_T>(io_context)
-  {
-  }
-
-  /// Construct an open acceptor.
-  /**
-   * This constructor creates an acceptor and automatically opens it.
-   *
-   * @param io_context The io_context object that the acceptor will use to
-   * dispatch handlers for any asynchronous operations performed on the
-   * acceptor.
-   *
-   * @param protocol An object specifying protocol parameters to be used.
-   *
-   * @throws asio::system_error Thrown on failure.
-   */
-  basic_socket_acceptor(asio::io_context& io_context,
-      const protocol_type& protocol)
-    : basic_io_object<ASIO_SVC_T>(io_context)
-  {
-    asio::error_code ec;
-    this->get_service().open(this->get_implementation(), protocol, ec);
-    asio::detail::throw_error(ec, "open");
-  }
-
-  /// Construct an acceptor opened on the given endpoint.
-  /**
-   * This constructor creates an acceptor and automatically opens it to listen
-   * for new connections on the specified endpoint.
-   *
-   * @param io_context The io_context object that the acceptor will use to
-   * dispatch handlers for any asynchronous operations performed on the
-   * acceptor.
-   *
-   * @param endpoint An endpoint on the local machine on which the acceptor
-   * will listen for new connections.
-   *
-   * @param reuse_addr Whether the constructor should set the socket option
-   * socket_base::reuse_address.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @note This constructor is equivalent to the following code:
-   * @code
-   * basic_socket_acceptor<Protocol> acceptor(io_context);
-   * acceptor.open(endpoint.protocol());
-   * if (reuse_addr)
-   *   acceptor.set_option(socket_base::reuse_address(true));
-   * acceptor.bind(endpoint);
-   * acceptor.listen(listen_backlog);
-   * @endcode
-   */
-  basic_socket_acceptor(asio::io_context& io_context,
-      const endpoint_type& endpoint, bool reuse_addr = true)
-    : basic_io_object<ASIO_SVC_T>(io_context)
-  {
-    asio::error_code ec;
-    const protocol_type protocol = endpoint.protocol();
-    this->get_service().open(this->get_implementation(), protocol, ec);
-    asio::detail::throw_error(ec, "open");
-    if (reuse_addr)
-    {
-      this->get_service().set_option(this->get_implementation(),
-          socket_base::reuse_address(true), ec);
-      asio::detail::throw_error(ec, "set_option");
-    }
-    this->get_service().bind(this->get_implementation(), endpoint, ec);
-    asio::detail::throw_error(ec, "bind");
-    this->get_service().listen(this->get_implementation(),
-        socket_base::max_listen_connections, ec);
-    asio::detail::throw_error(ec, "listen");
-  }
-
-  /// Construct a basic_socket_acceptor on an existing native acceptor.
-  /**
-   * This constructor creates an acceptor object to hold an existing native
-   * acceptor.
-   *
-   * @param io_context The io_context object that the acceptor will use to
-   * dispatch handlers for any asynchronous operations performed on the
-   * acceptor.
-   *
-   * @param protocol An object specifying protocol parameters to be used.
-   *
-   * @param native_acceptor A native acceptor.
-   *
-   * @throws asio::system_error Thrown on failure.
-   */
-  basic_socket_acceptor(asio::io_context& io_context,
-      const protocol_type& protocol, const native_handle_type& native_acceptor)
-    : basic_io_object<ASIO_SVC_T>(io_context)
-  {
-    asio::error_code ec;
-    this->get_service().assign(this->get_implementation(),
-        protocol, native_acceptor, ec);
-    asio::detail::throw_error(ec, "assign");
-  }
-
-#if defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
-  /// Move-construct a basic_socket_acceptor from another.
-  /**
-   * This constructor moves an acceptor from one object to another.
-   *
-   * @param other The other basic_socket_acceptor object from which the move
-   * will occur.
-   *
-   * @note Following the move, the moved-from object is in the same state as if
-   * constructed using the @c basic_socket_acceptor(io_context&) constructor.
-   */
-  basic_socket_acceptor(basic_socket_acceptor&& other)
-    : basic_io_object<ASIO_SVC_T>(std::move(other))
-  {
-  }
-
-  /// Move-assign a basic_socket_acceptor from another.
-  /**
-   * This assignment operator moves an acceptor from one object to another.
-   *
-   * @param other The other basic_socket_acceptor object from which the move
-   * will occur.
-   *
-   * @note Following the move, the moved-from object is in the same state as if
-   * constructed using the @c basic_socket_acceptor(io_context&) constructor.
-   */
-  basic_socket_acceptor& operator=(basic_socket_acceptor&& other)
-  {
-    basic_io_object<ASIO_SVC_T>::operator=(std::move(other));
-    return *this;
-  }
-
-  // All socket acceptors have access to each other's implementations.
-  template <typename Protocol1 ASIO_SVC_TPARAM1>
-  friend class basic_socket_acceptor;
-
-  /// Move-construct a basic_socket_acceptor from an acceptor of another
-  /// protocol type.
-  /**
-   * This constructor moves an acceptor from one object to another.
-   *
-   * @param other The other basic_socket_acceptor object from which the move
-   * will occur.
-   *
-   * @note Following the move, the moved-from object is in the same state as if
-   * constructed using the @c basic_socket(io_context&) constructor.
-   */
-  template <typename Protocol1 ASIO_SVC_TPARAM1>
-  basic_socket_acceptor(
-      basic_socket_acceptor<Protocol1 ASIO_SVC_TARG1>&& other,
-      typename enable_if<is_convertible<Protocol1, Protocol>::value>::type* = 0)
-    : basic_io_object<ASIO_SVC_T>(
-        other.get_service(), other.get_implementation())
-  {
-  }
-
-  /// Move-assign a basic_socket_acceptor from an acceptor of another protocol
-  /// type.
-  /**
-   * This assignment operator moves an acceptor from one object to another.
-   *
-   * @param other The other basic_socket_acceptor object from which the move
-   * will occur.
-   *
-   * @note Following the move, the moved-from object is in the same state as if
-   * constructed using the @c basic_socket(io_context&) constructor.
-   */
-  template <typename Protocol1 ASIO_SVC_TPARAM1>
-  typename enable_if<is_convertible<Protocol1, Protocol>::value,
-      basic_socket_acceptor>::type& operator=(
-        basic_socket_acceptor<Protocol1 ASIO_SVC_TARG1>&& other)
-  {
-    basic_socket_acceptor tmp(std::move(other));
-    basic_io_object<ASIO_SVC_T>::operator=(std::move(tmp));
-    return *this;
-  }
-#endif // defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
-
-  /// Destroys the acceptor.
-  /**
-   * This function destroys the acceptor, cancelling any outstanding
-   * asynchronous operations associated with the acceptor as if by calling
-   * @c cancel.
-   */
-  ~basic_socket_acceptor()
-  {
-  }
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  // These functions are provided by basic_io_object<>.
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-#if !defined(ASIO_NO_DEPRECATED)
-  /// (Deprecated: Use get_executor().) Get the io_context associated with the
-  /// object.
-  /**
-   * This function may be used to obtain the io_context object that the I/O
-   * object uses to dispatch handlers for asynchronous operations.
-   *
-   * @return A reference to the io_context object that the I/O object will use
-   * to dispatch handlers. Ownership is not transferred to the caller.
-   */
-  asio::io_context& get_io_context()
-  {
-    return basic_io_object<ASIO_SVC_T>::get_io_context();
-  }
-
-  /// (Deprecated: Use get_executor().) Get the io_context associated with the
-  /// object.
-  /**
-   * This function may be used to obtain the io_context object that the I/O
-   * object uses to dispatch handlers for asynchronous operations.
-   *
-   * @return A reference to the io_context object that the I/O object will use
-   * to dispatch handlers. Ownership is not transferred to the caller.
-   */
-  asio::io_context& get_io_service()
-  {
-    return basic_io_object<ASIO_SVC_T>::get_io_service();
-  }
-#endif // !defined(ASIO_NO_DEPRECATED)
-
-  /// Get the executor associated with the object.
-  executor_type get_executor() ASIO_NOEXCEPT
-  {
-    return basic_io_object<ASIO_SVC_T>::get_executor();
-  }
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
+  typedef asio::ssl::dtls::socket<DatagramSocketType> dtls_sock;
+
+  typedef typename DatagramSocketType::endpoint_type endpoint_type;
+  typedef typename DatagramSocketType::protocol_type protocol_type;
+
+  acceptor(asio::io_service &serv,
+                typename DatagramSocketType::endpoint_type &ep)
+    : service_(serv)
+    , sock_(serv)
+    , remoteEndPoint_()
+    , cookie_generate_callback_(nullptr)
+    , cookie_verify_callback_(nullptr)
+  {
+    sock_.open(ep.protocol());
+    asio::socket_base::reuse_address option(true);
+    sock_.set_option(option);
+  }
 
   /// Open the acceptor using the specified protocol.
   /**
@@ -345,7 +63,7 @@
   void open(const protocol_type& protocol = protocol_type())
   {
     asio::error_code ec;
-    this->get_service().open(this->get_implementation(), protocol, ec);
+    sock_.open(this->get_implementation(), protocol, ec);
     asio::detail::throw_error(ec, "open");
   }
 
@@ -370,53 +88,10 @@
    * @endcode
    */
   ASIO_SYNC_OP_VOID open(const protocol_type& protocol,
-      asio::error_code& ec)
-  {
-    this->get_service().open(this->get_implementation(), protocol, ec);
+                         asio::error_code& ec)
+  {
+    sock_.open(this->get_implementation(), protocol, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Assigns an existing native acceptor to the acceptor.
-  /*
-   * This function opens the acceptor to hold an existing native acceptor.
-   *
-   * @param protocol An object specifying which protocol is to be used.
-   *
-   * @param native_acceptor A native acceptor.
-   *
-   * @throws asio::system_error Thrown on failure.
-   */
-  void assign(const protocol_type& protocol,
-      const native_handle_type& native_acceptor)
-  {
-    asio::error_code ec;
-    this->get_service().assign(this->get_implementation(),
-        protocol, native_acceptor, ec);
-    asio::detail::throw_error(ec, "assign");
-  }
-
-  /// Assigns an existing native acceptor to the acceptor.
-  /*
-   * This function opens the acceptor to hold an existing native acceptor.
-   *
-   * @param protocol An object specifying which protocol is to be used.
-   *
-   * @param native_acceptor A native acceptor.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   */
-  ASIO_SYNC_OP_VOID assign(const protocol_type& protocol,
-      const native_handle_type& native_acceptor, asio::error_code& ec)
-  {
-    this->get_service().assign(this->get_implementation(),
-        protocol, native_acceptor, ec);
-    ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Determine whether the acceptor is open.
-  bool is_open() const
-  {
-    return this->get_service().is_open(this->get_implementation());
   }
 
   /// Bind the acceptor to the given local endpoint.
@@ -440,7 +115,7 @@
   void bind(const endpoint_type& endpoint)
   {
     asio::error_code ec;
-    this->get_service().bind(this->get_implementation(), endpoint, ec);
+    sock_.bind(endpoint, ec);
     asio::detail::throw_error(ec, "bind");
   }
 
@@ -468,54 +143,9 @@
    * @endcode
    */
   ASIO_SYNC_OP_VOID bind(const endpoint_type& endpoint,
-      asio::error_code& ec)
-  {
-    this->get_service().bind(this->get_implementation(), endpoint, ec);
-    ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Place the acceptor into the state where it will listen for new
-  /// connections.
-  /**
-   * This function puts the socket acceptor into the state where it may accept
-   * new connections.
-   *
-   * @param backlog The maximum length of the queue of pending connections.
-   *
-   * @throws asio::system_error Thrown on failure.
-   */
-  void listen(int backlog = socket_base::max_listen_connections)
-  {
-    asio::error_code ec;
-    this->get_service().listen(this->get_implementation(), backlog, ec);
-    asio::detail::throw_error(ec, "listen");
-  }
-
-  /// Place the acceptor into the state where it will listen for new
-  /// connections.
-  /**
-   * This function puts the socket acceptor into the state where it may accept
-   * new connections.
-   *
-   * @param backlog The maximum length of the queue of pending connections.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::error_code ec;
-   * acceptor.listen(asio::socket_base::max_listen_connections, ec);
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-  ASIO_SYNC_OP_VOID listen(int backlog, asio::error_code& ec)
-  {
-    this->get_service().listen(this->get_implementation(), backlog, ec);
+                         asio::error_code& ec)
+  {
+    sock_.bind(endpoint, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -562,69 +192,6 @@
   {
     this->get_service().close(this->get_implementation(), ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Release ownership of the underlying native acceptor.
-  /**
-   * This function causes all outstanding asynchronous accept operations to
-   * finish immediately, and the handlers for cancelled operations will be
-   * passed the asio::error::operation_aborted error. Ownership of the
-   * native acceptor is then transferred to the caller.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @note This function is unsupported on Windows versions prior to Windows
-   * 8.1, and will fail with asio::error::operation_not_supported on
-   * these platforms.
-   */
-#if defined(ASIO_MSVC) && (ASIO_MSVC >= 1400) \
-  && (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0603)
-  __declspec(deprecated("This function always fails with "
-        "operation_not_supported when used on Windows versions "
-        "prior to Windows 8.1."))
-#endif
-  native_handle_type release()
-  {
-    asio::error_code ec;
-    native_handle_type s = this->get_service().release(
-        this->get_implementation(), ec);
-    asio::detail::throw_error(ec, "release");
-    return s;
-  }
-
-  /// Release ownership of the underlying native acceptor.
-  /**
-   * This function causes all outstanding asynchronous accept operations to
-   * finish immediately, and the handlers for cancelled operations will be
-   * passed the asio::error::operation_aborted error. Ownership of the
-   * native acceptor is then transferred to the caller.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @note This function is unsupported on Windows versions prior to Windows
-   * 8.1, and will fail with asio::error::operation_not_supported on
-   * these platforms.
-   */
-#if defined(ASIO_MSVC) && (ASIO_MSVC >= 1400) \
-  && (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0603)
-  __declspec(deprecated("This function always fails with "
-        "operation_not_supported when used on Windows versions "
-        "prior to Windows 8.1."))
-#endif
-  native_handle_type release(asio::error_code& ec)
-  {
-    return this->get_service().release(this->get_implementation(), ec);
-  }
-
-  /// Get the native acceptor representation.
-  /**
-   * This function may be used to obtain the underlying representation of the
-   * acceptor. This is intended to allow access to native acceptor functionality
-   * that is not otherwise provided.
-   */
-  native_handle_type native_handle()
-  {
-    return this->get_service().native_handle(this->get_implementation());
   }
 
   /// Cancel all asynchronous operations associated with the acceptor.
@@ -713,7 +280,7 @@
    */
   template <typename SettableSocketOption>
   ASIO_SYNC_OP_VOID set_option(const SettableSocketOption& option,
-      asio::error_code& ec)
+                               asio::error_code& ec)
   {
     this->get_service().set_option(this->get_implementation(), option, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
@@ -778,10 +345,35 @@
    */
   template <typename GettableSocketOption>
   ASIO_SYNC_OP_VOID get_option(GettableSocketOption& option,
-      asio::error_code& ec)
+                               asio::error_code& ec)
   {
     this->get_service().get_option(this->get_implementation(), option, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
+  }
+
+  template <typename CookieGenerateCallback>
+  void set_cookie_generate_callback(CookieGenerateCallback callback)
+  {
+    if (cookie_generate_callback_)
+    {
+      delete cookie_generate_callback_;
+    }
+
+    cookie_generate_callback_ =
+        new detail::cookie_generate_callback<typename DatagramSocketType::endpoint_type, CookieGenerateCallback>(callback);
+  }
+
+  template <typename CookieCallback>
+  void set_cookie_verify_callback(CookieCallback callback)
+  {
+    if (cookie_verify_callback_)
+    {
+      delete cookie_verify_callback_;
+    }
+
+    cookie_verify_callback_ =
+        new detail::cookie_verify_callback
+        <typename DatagramSocketType::endpoint_type, CookieCallback>(callback);
   }
 
   /// Perform an IO control command on the acceptor.
@@ -839,7 +431,7 @@
    */
   template <typename IoControlCommand>
   ASIO_SYNC_OP_VOID io_control(IoControlCommand& command,
-      asio::error_code& ec)
+                               asio::error_code& ec)
   {
     this->get_service().io_control(this->get_implementation(), command, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
@@ -939,7 +531,7 @@
   {
     asio::error_code ec;
     this->get_service().native_non_blocking(
-        this->get_implementation(), mode, ec);
+          this->get_implementation(), mode, ec);
     asio::detail::throw_error(ec, "native_non_blocking");
   }
 
@@ -962,7 +554,7 @@
       bool mode, asio::error_code& ec)
   {
     this->get_service().native_non_blocking(
-        this->get_implementation(), mode, ec);
+          this->get_implementation(), mode, ec);
     ASIO_SYNC_OP_VOID_RETURN(ec);
   }
 
@@ -985,7 +577,7 @@
   {
     asio::error_code ec;
     endpoint_type ep = this->get_service().local_endpoint(
-        this->get_implementation(), ec);
+                         this->get_implementation(), ec);
     asio::detail::throw_error(ec, "local_endpoint");
     return ep;
   }
@@ -1017,116 +609,6 @@
     return this->get_service().local_endpoint(this->get_implementation(), ec);
   }
 
-  /// Wait for the acceptor to become ready to read, ready to write, or to have
-  /// pending error conditions.
-  /**
-   * This function is used to perform a blocking wait for an acceptor to enter
-   * a ready to read, write or error condition state.
-   *
-   * @param w Specifies the desired acceptor state.
-   *
-   * @par Example
-   * Waiting for an acceptor to become readable.
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * acceptor.wait(asio::ip::tcp::acceptor::wait_read);
-   * @endcode
-   */
-  void wait(wait_type w)
-  {
-    asio::error_code ec;
-    this->get_service().wait(this->get_implementation(), w, ec);
-    asio::detail::throw_error(ec, "wait");
-  }
-
-  /// Wait for the acceptor to become ready to read, ready to write, or to have
-  /// pending error conditions.
-  /**
-   * This function is used to perform a blocking wait for an acceptor to enter
-   * a ready to read, write or error condition state.
-   *
-   * @param w Specifies the desired acceptor state.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @par Example
-   * Waiting for an acceptor to become readable.
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::error_code ec;
-   * acceptor.wait(asio::ip::tcp::acceptor::wait_read, ec);
-   * @endcode
-   */
-  ASIO_SYNC_OP_VOID wait(wait_type w, asio::error_code& ec)
-  {
-    this->get_service().wait(this->get_implementation(), w, ec);
-    ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Asynchronously wait for the acceptor to become ready to read, ready to
-  /// write, or to have pending error conditions.
-  /**
-   * This function is used to perform an asynchronous wait for an acceptor to
-   * enter a ready to read, write or error condition state.
-   *
-   * @param w Specifies the desired acceptor state.
-   *
-   * @param handler The handler to be called when the wait operation completes.
-   * Copies will be made of the handler as required. The function signature of
-   * the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error // Result of operation
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   *
-   * @par Example
-   * @code
-   * void wait_handler(const asio::error_code& error)
-   * {
-   *   if (!error)
-   *   {
-   *     // Wait succeeded.
-   *   }
-   * }
-   *
-   * ...
-   *
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * acceptor.async_wait(
-   *     asio::ip::tcp::acceptor::wait_read,
-   *     wait_handler);
-   * @endcode
-   */
-  template <typename WaitHandler>
-  ASIO_INITFN_RESULT_TYPE(WaitHandler,
-      void (asio::error_code))
-  async_wait(wait_type w, ASIO_MOVE_ARG(WaitHandler) handler)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a WaitHandler.
-    ASIO_WAIT_HANDLER_CHECK(WaitHandler, handler) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_wait(this->get_implementation(),
-        w, ASIO_MOVE_CAST(WaitHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<WaitHandler,
-      void (asio::error_code)> init(handler);
-
-    this->get_service().async_wait(this->get_implementation(),
-        w, init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-
-#if !defined(ASIO_NO_EXTENSIONS)
   /// Accept a new connection.
   /**
    * This function is used to accept a new connection from a peer into the
@@ -1148,340 +630,27 @@
 #if defined(ASIO_ENABLE_OLD_SERVICES)
   template <typename Protocol1, typename SocketService>
   void accept(basic_socket<Protocol1, SocketService>& peer,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
+              typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
 #else // defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename Protocol1>
-  void accept(basic_socket<Protocol1>& peer,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
+  void accept(socket<DatagramSocketType>& peer)
 #endif // defined(ASIO_ENABLE_OLD_SERVICES)
   {
     asio::error_code ec;
     this->get_service().accept(this->get_implementation(),
-        peer, static_cast<endpoint_type*>(0), ec);
+                               peer, static_cast<endpoint_type*>(0), ec);
     asio::detail::throw_error(ec, "accept");
   }
 
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer into the
-   * given socket. The function call will block until a new connection has been
-   * accepted successfully or an error occurs.
-   *
-   * @param peer The socket into which the new connection will be accepted.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(io_context);
-   * asio::error_code ec;
-   * acceptor.accept(socket, ec);
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename Protocol1, typename SocketService>
-  ASIO_SYNC_OP_VOID accept(
-      basic_socket<Protocol1, SocketService>& peer,
-      asio::error_code& ec,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename Protocol1>
-  ASIO_SYNC_OP_VOID accept(
-      basic_socket<Protocol1>& peer, asio::error_code& ec,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  {
-    this->get_service().accept(this->get_implementation(),
-        peer, static_cast<endpoint_type*>(0), ec);
-    ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
   /// Start an asynchronous accept.
   /**
-   * This function is used to asynchronously accept a new connection into a
-   * socket. The function call always returns immediately.
-   *
-   * @param peer The socket into which the new connection will be accepted.
-   * Ownership of the peer object is retained by the caller, which must
-   * guarantee that it is valid until the handler is called.
-   *
-   * @param handler The handler to be called when the accept operation
-   * completes. Copies will be made of the handler as required. The function
-   * signature of the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error // Result of operation.
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   *
-   * @par Example
-   * @code
-   * void accept_handler(const asio::error_code& error)
-   * {
-   *   if (!error)
-   *   {
-   *     // Accept succeeded.
-   *   }
-   * }
-   *
-   * ...
-   *
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(io_context);
-   * acceptor.async_accept(socket, accept_handler);
-   * @endcode
-   */
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename Protocol1, typename SocketService, typename AcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(AcceptHandler,
-      void (asio::error_code))
-  async_accept(basic_socket<Protocol1, SocketService>& peer,
-      ASIO_MOVE_ARG(AcceptHandler) handler,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename Protocol1, typename AcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(AcceptHandler,
-      void (asio::error_code))
-  async_accept(basic_socket<Protocol1>& peer,
-      ASIO_MOVE_ARG(AcceptHandler) handler,
-      typename enable_if<is_convertible<Protocol, Protocol1>::value>::type* = 0)
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a AcceptHandler.
-    ASIO_ACCEPT_HANDLER_CHECK(AcceptHandler, handler) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(this->get_implementation(),
-        peer, static_cast<endpoint_type*>(0),
-        ASIO_MOVE_CAST(AcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<AcceptHandler,
-      void (asio::error_code)> init(handler);
-
-    this->get_service().async_accept(this->get_implementation(),
-        peer, static_cast<endpoint_type*>(0), init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-
-  /// Accept a new connection and obtain the endpoint of the peer
-  /**
-   * This function is used to accept a new connection from a peer into the
-   * given socket, and additionally provide the endpoint of the remote peer.
-   * The function call will block until a new connection has been accepted
-   * successfully or an error occurs.
-   *
-   * @param peer The socket into which the new connection will be accepted.
-   *
-   * @param peer_endpoint An endpoint object which will receive the endpoint of
-   * the remote peer.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(io_context);
-   * asio::ip::tcp::endpoint endpoint;
-   * acceptor.accept(socket, endpoint);
-   * @endcode
-   */
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename SocketService>
-  void accept(basic_socket<protocol_type, SocketService>& peer,
-      endpoint_type& peer_endpoint)
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-  void accept(basic_socket<protocol_type>& peer, endpoint_type& peer_endpoint)
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  {
-    asio::error_code ec;
-    this->get_service().accept(this->get_implementation(),
-        peer, &peer_endpoint, ec);
-    asio::detail::throw_error(ec, "accept");
-  }
-
-  /// Accept a new connection and obtain the endpoint of the peer
-  /**
-   * This function is used to accept a new connection from a peer into the
-   * given socket, and additionally provide the endpoint of the remote peer.
-   * The function call will block until a new connection has been accepted
-   * successfully or an error occurs.
-   *
-   * @param peer The socket into which the new connection will be accepted.
-   *
-   * @param peer_endpoint An endpoint object which will receive the endpoint of
-   * the remote peer.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(io_context);
-   * asio::ip::tcp::endpoint endpoint;
-   * asio::error_code ec;
-   * acceptor.accept(socket, endpoint, ec);
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename SocketService>
-  ASIO_SYNC_OP_VOID accept(
-      basic_socket<protocol_type, SocketService>& peer,
-      endpoint_type& peer_endpoint, asio::error_code& ec)
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-  ASIO_SYNC_OP_VOID accept(basic_socket<protocol_type>& peer,
-      endpoint_type& peer_endpoint, asio::error_code& ec)
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  {
-    this->get_service().accept(
-        this->get_implementation(), peer, &peer_endpoint, ec);
-    ASIO_SYNC_OP_VOID_RETURN(ec);
-  }
-
-  /// Start an asynchronous accept.
-  /**
-   * This function is used to asynchronously accept a new connection into a
-   * socket, and additionally obtain the endpoint of the remote peer. The
+   * This function is used to asynchronously accept a new connection. The
    * function call always returns immediately.
-   *
-   * @param peer The socket into which the new connection will be accepted.
-   * Ownership of the peer object is retained by the caller, which must
-   * guarantee that it is valid until the handler is called.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written. Ownership of the peer_endpoint object is
-   * retained by the caller, which must guarantee that it is valid until the
-   * handler is called.
-   *
-   * @param handler The handler to be called when the accept operation
-   * completes. Copies will be made of the handler as required. The function
-   * signature of the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error // Result of operation.
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   */
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename SocketService, typename AcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(AcceptHandler,
-      void (asio::error_code))
-  async_accept(basic_socket<protocol_type, SocketService>& peer,
-      endpoint_type& peer_endpoint, ASIO_MOVE_ARG(AcceptHandler) handler)
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-  template <typename AcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(AcceptHandler,
-      void (asio::error_code))
-  async_accept(basic_socket<protocol_type>& peer,
-      endpoint_type& peer_endpoint, ASIO_MOVE_ARG(AcceptHandler) handler)
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a AcceptHandler.
-    ASIO_ACCEPT_HANDLER_CHECK(AcceptHandler, handler) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(this->get_implementation(), peer,
-        &peer_endpoint, ASIO_MOVE_CAST(AcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<AcceptHandler,
-      void (asio::error_code)> init(handler);
-
-    this->get_service().async_accept(this->get_implementation(),
-        peer, &peer_endpoint, init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-#endif // !defined(ASIO_NO_EXTENSIONS)
-
-#if defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
    *
    * This overload requires that the Protocol template parameter satisfy the
    * AcceptableProtocol type requirements.
    *
-   * @returns A socket object representing the newly accepted connection.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(acceptor.accept());
-   * @endcode
-   */
-  typename Protocol::socket accept()
-  {
-    asio::error_code ec;
-    typename Protocol::socket peer(
-        this->get_service().accept(
-          this->get_implementation(), 0, 0, ec));
-    asio::detail::throw_error(ec, "accept");
-    return peer;
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @returns On success, a socket object representing the newly accepted
-   * connection. On error, a socket object where is_open() is false.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(acceptor.accept(ec));
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-  typename Protocol::socket accept(asio::error_code& ec)
-  {
-    return this->get_service().accept(this->get_implementation(), 0, 0, ec);
-  }
-
-  /// Start an asynchronous accept.
-  /**
-   * This function is used to asynchronously accept a new connection. The
-   * function call always returns immediately.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
+   * @param io_context The io_context object to be used for the newly accepted
+   * socket.
    *
    * @param handler The handler to be called when the accept operation
    * completes. Copies will be made of the handler as required. The function
@@ -1510,477 +679,146 @@
    *
    * asio::ip::tcp::acceptor acceptor(io_context);
    * ...
-   * acceptor.async_accept(accept_handler);
-   * @endcode
-   */
-  template <typename MoveAcceptHandler>
+   * acceptor.async_accept(io_context2, accept_handler);
+   * @endcode
+   */
+  template <typename MoveAcceptHandler, typename MutableBuffer>
   ASIO_INITFN_RESULT_TYPE(MoveAcceptHandler,
-      void (asio::error_code, typename Protocol::socket))
-  async_accept(ASIO_MOVE_ARG(MoveAcceptHandler) handler)
+                          void (asio::error_code, DatagramSocketType))
+  async_accept(socket<DatagramSocketType> &sock,
+               const MutableBuffer& buffer,
+               ASIO_MOVE_ARG(MoveAcceptHandler) handler,
+               asio::error_code &ec)
   {
     // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a MoveAcceptHandler.
-    ASIO_MOVE_ACCEPT_HANDLER_CHECK(MoveAcceptHandler,
-        handler, typename Protocol::socket) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(
-        this->get_implementation(), static_cast<asio::io_context*>(0),
-        static_cast<endpoint_type*>(0),
-        ASIO_MOVE_CAST(MoveAcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
+    // not meet the documented type requirements for a ReceiveHandler.
+    ASIO_READ_HANDLER_CHECK(MoveAcceptHandler, handler) type_check;
+
     async_completion<MoveAcceptHandler,
-      void (asio::error_code,
-        typename Protocol::socket)> init(handler);
-
-    this->get_service().async_accept(
-        this->get_implementation(), static_cast<asio::io_context*>(0),
-        static_cast<endpoint_type*>(0), init.completion_handler);
+        void (asio::error_code,
+              size_t)> init(handler);
+
+    if(cookie_generate_callback_ == nullptr ||
+       cookie_verify_callback_ == nullptr)
+    {
+#if (OPENSSL_VERSION_NUMBER >= 0x10100000)
+      ::SSLerr(
+        SSL_F_DTLSV1_LISTEN,
+        SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
+#endif
+      ec = asio::error_code(::ERR_get_error(),
+                            asio::error::get_ssl_category());
+      return;
+    }
+
+    sock.set_cookie_generate_callback(*cookie_generate_callback_, ec);
+    if(ec)
+    {
+      return;
+    }
+
+    sock.set_cookie_verify_callback(*cookie_verify_callback_, ec);
+    if(ec)
+    {
+      return;
+    }
+
+    sock_.async_receive_from(buffer,
+                            remoteEndPoint_,
+    dtls_acceptor_callback_helper<MoveAcceptHandler>(*this, init.completion_handler, sock, buffer));
 
     return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @returns A socket object representing the newly accepted connection.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(acceptor.accept());
-   * @endcode
-   */
-  typename Protocol::socket accept(asio::io_context& io_context)
-  {
-    asio::error_code ec;
-    typename Protocol::socket peer(
-        this->get_service().accept(this->get_implementation(),
-          &io_context, static_cast<endpoint_type*>(0), ec));
-    asio::detail::throw_error(ec, "accept");
-    return peer;
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @returns On success, a socket object representing the newly accepted
-   * connection. On error, a socket object where is_open() is false.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::socket socket(acceptor.accept(io_context2, ec));
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-  typename Protocol::socket accept(
-      asio::io_context& io_context, asio::error_code& ec)
-  {
-    return this->get_service().accept(this->get_implementation(),
-        &io_context, static_cast<endpoint_type*>(0), ec);
-  }
-
-  /// Start an asynchronous accept.
-  /**
-   * This function is used to asynchronously accept a new connection. The
-   * function call always returns immediately.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @param handler The handler to be called when the accept operation
-   * completes. Copies will be made of the handler as required. The function
-   * signature of the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error, // Result of operation.
-   *   typename Protocol::socket peer // On success, the newly accepted socket.
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   *
-   * @par Example
-   * @code
-   * void accept_handler(const asio::error_code& error,
-   *     asio::ip::tcp::socket peer)
-   * {
-   *   if (!error)
-   *   {
-   *     // Accept succeeded.
-   *   }
-   * }
-   *
-   * ...
-   *
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * acceptor.async_accept(io_context2, accept_handler);
-   * @endcode
-   */
-  template <typename MoveAcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(MoveAcceptHandler,
-      void (asio::error_code, typename Protocol::socket))
-  async_accept(asio::io_context& io_context,
-      ASIO_MOVE_ARG(MoveAcceptHandler) handler)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a MoveAcceptHandler.
-    ASIO_MOVE_ACCEPT_HANDLER_CHECK(MoveAcceptHandler,
-        handler, typename Protocol::socket) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(this->get_implementation(),
-        &io_context, static_cast<endpoint_type*>(0),
-        ASIO_MOVE_CAST(MoveAcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<MoveAcceptHandler,
-      void (asio::error_code,
-        typename Protocol::socket)> init(handler);
-
-    this->get_service().async_accept(this->get_implementation(),
-        &io_context, static_cast<endpoint_type*>(0), init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written.
-   *
-   * @returns A socket object representing the newly accepted connection.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * asio::ip::tcp::socket socket(acceptor.accept(endpoint));
-   * @endcode
-   */
-  typename Protocol::socket accept(endpoint_type& peer_endpoint)
-  {
-    asio::error_code ec;
-    typename Protocol::socket peer(
-        this->get_service().accept(this->get_implementation(),
-          static_cast<asio::io_context*>(0), &peer_endpoint, ec));
-    asio::detail::throw_error(ec, "accept");
-    return peer;
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @returns On success, a socket object representing the newly accepted
-   * connection. On error, a socket object where is_open() is false.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * asio::ip::tcp::socket socket(acceptor.accept(endpoint, ec));
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-  typename Protocol::socket accept(
-      endpoint_type& peer_endpoint, asio::error_code& ec)
-  {
-    return this->get_service().accept(this->get_implementation(),
-        static_cast<asio::io_context*>(0), &peer_endpoint, ec);
-  }
-
-  /// Start an asynchronous accept.
-  /**
-   * This function is used to asynchronously accept a new connection. The
-   * function call always returns immediately.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written. Ownership of the peer_endpoint object is
-   * retained by the caller, which must guarantee that it is valid until the
-   * handler is called.
-   *
-   * @param handler The handler to be called when the accept operation
-   * completes. Copies will be made of the handler as required. The function
-   * signature of the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error, // Result of operation.
-   *   typename Protocol::socket peer // On success, the newly accepted socket.
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   *
-   * @par Example
-   * @code
-   * void accept_handler(const asio::error_code& error,
-   *     asio::ip::tcp::socket peer)
-   * {
-   *   if (!error)
-   *   {
-   *     // Accept succeeded.
-   *   }
-   * }
-   *
-   * ...
-   *
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * acceptor.async_accept(endpoint, accept_handler);
-   * @endcode
-   */
-  template <typename MoveAcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(MoveAcceptHandler,
-      void (asio::error_code, typename Protocol::socket))
-  async_accept(endpoint_type& peer_endpoint,
-      ASIO_MOVE_ARG(MoveAcceptHandler) handler)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a MoveAcceptHandler.
-    ASIO_MOVE_ACCEPT_HANDLER_CHECK(MoveAcceptHandler,
-        handler, typename Protocol::socket) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(this->get_implementation(),
-        static_cast<asio::io_context*>(0), &peer_endpoint,
-        ASIO_MOVE_CAST(MoveAcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<MoveAcceptHandler,
-      void (asio::error_code,
-        typename Protocol::socket)> init(handler);
-
-    this->get_service().async_accept(this->get_implementation(),
-        static_cast<asio::io_context*>(0), &peer_endpoint,
-        init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written.
-   *
-   * @returns A socket object representing the newly accepted connection.
-   *
-   * @throws asio::system_error Thrown on failure.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * asio::ip::tcp::socket socket(
-   *     acceptor.accept(io_context2, endpoint));
-   * @endcode
-   */
-  typename Protocol::socket accept(
-      asio::io_context& io_context, endpoint_type& peer_endpoint)
-  {
-    asio::error_code ec;
-    typename Protocol::socket peer(
-        this->get_service().accept(this->get_implementation(),
-          &io_context, &peer_endpoint, ec));
-    asio::detail::throw_error(ec, "accept");
-    return peer;
-  }
-
-  /// Accept a new connection.
-  /**
-   * This function is used to accept a new connection from a peer. The function
-   * call will block until a new connection has been accepted successfully or
-   * an error occurs.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written.
-   *
-   * @param ec Set to indicate what error occurred, if any.
-   *
-   * @returns On success, a socket object representing the newly accepted
-   * connection. On error, a socket object where is_open() is false.
-   *
-   * @par Example
-   * @code
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * asio::ip::tcp::socket socket(
-   *     acceptor.accept(io_context2, endpoint, ec));
-   * if (ec)
-   * {
-   *   // An error occurred.
-   * }
-   * @endcode
-   */
-  typename Protocol::socket accept(asio::io_context& io_context,
-      endpoint_type& peer_endpoint, asio::error_code& ec)
-  {
-    return this->get_service().accept(this->get_implementation(),
-        &io_context, &peer_endpoint, ec);
-  }
-
-  /// Start an asynchronous accept.
-  /**
-   * This function is used to asynchronously accept a new connection. The
-   * function call always returns immediately.
-   *
-   * This overload requires that the Protocol template parameter satisfy the
-   * AcceptableProtocol type requirements.
-   *
-   * @param io_context The io_context object to be used for the newly accepted
-   * socket.
-   *
-   * @param peer_endpoint An endpoint object into which the endpoint of the
-   * remote peer will be written. Ownership of the peer_endpoint object is
-   * retained by the caller, which must guarantee that it is valid until the
-   * handler is called.
-   *
-   * @param handler The handler to be called when the accept operation
-   * completes. Copies will be made of the handler as required. The function
-   * signature of the handler must be:
-   * @code void handler(
-   *   const asio::error_code& error, // Result of operation.
-   *   typename Protocol::socket peer // On success, the newly accepted socket.
-   * ); @endcode
-   * Regardless of whether the asynchronous operation completes immediately or
-   * not, the handler will not be invoked from within this function. Invocation
-   * of the handler will be performed in a manner equivalent to using
-   * asio::io_context::post().
-   *
-   * @par Example
-   * @code
-   * void accept_handler(const asio::error_code& error,
-   *     asio::ip::tcp::socket peer)
-   * {
-   *   if (!error)
-   *   {
-   *     // Accept succeeded.
-   *   }
-   * }
-   *
-   * ...
-   *
-   * asio::ip::tcp::acceptor acceptor(io_context);
-   * ...
-   * asio::ip::tcp::endpoint endpoint;
-   * acceptor.async_accept(io_context2, endpoint, accept_handler);
-   * @endcode
-   */
-  template <typename MoveAcceptHandler>
-  ASIO_INITFN_RESULT_TYPE(MoveAcceptHandler,
-      void (asio::error_code, typename Protocol::socket))
-  async_accept(asio::io_context& io_context,
-      endpoint_type& peer_endpoint,
-      ASIO_MOVE_ARG(MoveAcceptHandler) handler)
-  {
-    // If you get an error on the following line it means that your handler does
-    // not meet the documented type requirements for a MoveAcceptHandler.
-    ASIO_MOVE_ACCEPT_HANDLER_CHECK(MoveAcceptHandler,
-        handler, typename Protocol::socket) type_check;
-
-#if defined(ASIO_ENABLE_OLD_SERVICES)
-    return this->get_service().async_accept(
-        this->get_implementation(), &io_context, &peer_endpoint,
-        ASIO_MOVE_CAST(MoveAcceptHandler)(handler));
-#else // defined(ASIO_ENABLE_OLD_SERVICES)
-    async_completion<MoveAcceptHandler,
-      void (asio::error_code,
-        typename Protocol::socket)> init(handler);
-
-    this->get_service().async_accept(this->get_implementation(),
-        &io_context, &peer_endpoint, init.completion_handler);
-
-    return init.result.get();
-#endif // defined(ASIO_ENABLE_OLD_SERVICES)
-  }
-#endif // defined(ASIO_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
+  }
+
+  /// Get the service associated with the I/O object.
+  asio::io_service& get_service()
+  {
+    return service_;
+  }
+
+  /// Get the service associated with the I/O object.
+  const asio::io_service& get_service() const
+  {
+    return service_;
+  }
+
+private:
+
+  template <typename AcceptHandler>
+  class dtls_acceptor_callback_helper
+  {
+  public:
+    dtls_acceptor_callback_helper(acceptor<DatagramSocketType> &acc,
+                                  AcceptHandler& ah,
+                                  socket<DatagramSocketType>& sock,
+                                  asio::mutable_buffer buffer)
+      : acceptor_(acc)
+      , ah_(std::move(ah))
+      , sock_(sock)
+      , buffer_(buffer)
+      , work_(acc.sock_.get_executor())
+    {
+    }
+
+    void operator ()(const asio::error_code& ec, size_t size)
+    {
+      if(ec)
+      {
+        ah_(ec, size);
+      }
+      else
+      {
+        asio::error_code ec;
+        if (sock_.verify_cookie(acceptor_.sock_,
+                            buffer_,
+                            ec, acceptor_.remoteEndPoint_))
+        {
+          sock_.next_layer().open(acceptor_.sock_.local_endpoint().protocol());
+
+          asio::socket_base::reuse_address option(true);
+          sock_.next_layer().set_option(option);
+          sock_.next_layer().bind(acceptor_.sock_.local_endpoint());
+
+          sock_.next_layer().connect(acceptor_.remoteEndPoint_);
+
+          ah_(ec, size);
+        }
+        else
+        {
+          acceptor_.sock_.async_receive_from(
+             buffer_, acceptor_.remoteEndPoint_, *this);
+        }
+      }
+    }
+
+    using executor_type = asio::associated_executor_t<
+        AcceptHandler, decltype(std::declval<DatagramSocketType&>().get_executor())>;
+
+    executor_type get_executor() const noexcept
+    {
+        return (asio::get_associated_executor)(ah_, sock_.get_executor());
+    }
+
+  private:
+    acceptor<DatagramSocketType> &acceptor_;
+    AcceptHandler ah_;
+    socket<DatagramSocketType> &sock_;
+    asio::mutable_buffer buffer_;
+    asio::executor_work_guard<executor_type> work_;
+  };
+
+
+  io_service& service_;
+  DatagramSocketType sock_;
+  typename DatagramSocketType::endpoint_type remoteEndPoint_;
+  detail::cookie_generate_callback_base* cookie_generate_callback_;
+  detail::cookie_verify_callback_base* cookie_verify_callback_;
 };
 
+} // namespace dtls
+} // namespace ssl
 } // namespace asio
 
 #include "asio/detail/pop_options.hpp"
 
-#if !defined(ASIO_ENABLE_OLD_SERVICES)
-# undef ASIO_SVC_T
-#endif // !defined(ASIO_ENABLE_OLD_SERVICES)
-
-#endif // ASIO_BASIC_SOCKET_ACCEPTOR_HPP
+#endif // ASIO_DTLS_ACCEPTOR_HPP

