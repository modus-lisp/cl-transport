;;;; src/connect.lisp — the one place a carrier opens a TCP connection.
;;;;
;;;; Every outbound carrier (:direct, :socks5, :http-connect) connects through here, on
;;;; sb-bsd-sockets, so none of them needs usocket.  The gate still sees the connection:
;;;; it hooks sb-bsd-sockets:socket-connect, and this calls it.
;;;;
;;;; TIMEOUT BOUNDS THE CONNECT ONLY.  usocket's :timeout did the same, and it is not a
;;;; read timeout: a tunnel that is quiet for longer than the dial timeout is not an
;;;; error.  The stream is therefore made without a read timeout.
;;;;
;;;; HOW THE CONNECT IS BOUNDED.  A blocking connect is not interrupted by a deadline:
;;;; SB-SYS:WITH-DEADLINE leaves a connect to an unroutable host blocked for the kernel's
;;;; full SYN retry period, measured at over two minutes.  So a timed connect is
;;;; NON-BLOCKING: it starts, the kernel reports EINPROGRESS, and SB-SYS:WAIT-UNTIL-FD-
;;;; USABLE waits for the socket to become writable or the timeout to pass.  A socket
;;;; that became writable because the connect FAILED is told apart by its peer name,
;;;; which does not exist on an unconnected socket.
;;;;
;;;; ON MODUS THE CONNECT IS THE KERNEL'S.  modus's sb-bsd-sockets has no non-blocking
;;;; mode (its shim has no (SETF NON-BLOCKING-MODE)), so there a connect blocks until it
;;;; finishes or the kernel gives up, exactly as cl-transport/sockets' TCP-CONNECT does.
;;;; modus pushes :SB-BSD-SOCKETS and not :SBCL, which is what #-sbcl selects.

(defpackage #:cl-transport.connect
  (:use #:cl)
  (:export #:connect-tcp))

(in-package #:cl-transport.connect)

#+sbcl
(defun %connect-within (host port timeout)
  "A connected socket and its binary stream, or an error after TIMEOUT seconds."
  (let* ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (fd (sb-bsd-sockets:socket-file-descriptor sock))
         (address (sb-bsd-sockets:host-ent-address
                   (sb-bsd-sockets:get-host-by-name host))))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (sb-bsd-sockets:socket-close sock)))))
      (setf (sb-bsd-sockets:non-blocking-mode sock) t)
      (handler-case (sb-bsd-sockets:socket-connect sock address port)
        (sb-bsd-sockets:operation-in-progress () nil))
      (unless (sb-sys:wait-until-fd-usable fd :output timeout)
        (error "cl-transport: connect to ~a:~d timed out after ~a s" host port timeout))
      ;; A failed connect is writable too.  Only a connected socket has a peer name.
      (sb-bsd-sockets:socket-peername sock)
      (setf (sb-bsd-sockets:non-blocking-mode sock) nil
            (sb-bsd-sockets:sockopt-tcp-nodelay sock) t)
      (values sock
              (sb-bsd-sockets:socket-make-stream sock :input t :output t
                                                      :element-type '(unsigned-byte 8)
                                                      :buffering :full)))))

(defun connect-tcp (host port &key timeout)
  "Connect to HOST:PORT.  Returns (values SOCKET STREAM): a binary stream, and the
   socket to close when the stream is done with.  Signals if the connect fails or runs
   past TIMEOUT seconds, when one is given."
  #+sbcl
  (if timeout
      (%connect-within host port timeout)
      (cl-transport.listeners:open-connection :host host :port port))
  #-sbcl
  (progn timeout (cl-transport.listeners:open-connection :host host :port port)))
