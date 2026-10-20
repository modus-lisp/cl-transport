;;;; http-connect.lisp — the :HTTP-CONNECT carrier, against a real CONNECT proxy.
;;;;
;;;;   sbcl --script inspect/http-connect.lisp
;;;;
;;;; Nothing beyond SBCL: the carrier, the proxy and the echo server are all sb-bsd-sockets
;;;; and sb-thread.  Every socket is 127.0.0.1 on an ephemeral port.  The proxy is a
;;;; loopback thread that speaks CONNECT and then copies bytes, and it records what it
;;;; was asked, so each check is about what crossed the wire and not about what this
;;;; file meant to send.

(require :asdf)
(require :sb-bsd-sockets)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport")))

(defpackage #:http-connect-test (:use #:cl)) (in-package #:http-connect-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got expect)
  (if (equal got expect)
      (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a~%       got    ~s~%       expect ~s~%" name got expect))))

(defun crlf-bytes (s) (map '(vector (unsigned-byte 8)) #'char-code s))
(defun bytes->string (v) (map 'string #'code-char v))

;;; ---- loopback listeners -----------------------------------------------------------

(defun listen-loopback ()
  "A listening socket on 127.0.0.1 and its port."
  (let ((srv (cl-transport.listeners:tcp-listen 0 :address "127.0.0.1")))
    (values srv (nth-value 1 (sb-bsd-sockets:socket-name srv)))))

(defun accept-stream (srv)
  "The next connection on SRV: (values socket binary-stream)."
  (let ((c (sb-bsd-sockets:socket-accept srv)))
    (values c (sb-bsd-sockets:socket-make-stream c :input t :output t
                                                    :element-type '(unsigned-byte 8)
                                                    :buffering :full))))

;;; ---- the echo target --------------------------------------------------------------

(defun start-echo ()
  (multiple-value-bind (srv port) (listen-loopback)
    (sb-thread:make-thread
     (lambda ()
       (loop
         (multiple-value-bind (c s) (accept-stream srv)
           (sb-thread:make-thread
            (lambda ()
              (ignore-errors
               (loop for b = (read-byte s nil nil) while b do (write-byte b s) (finish-output s)))
              (ignore-errors (sb-bsd-sockets:socket-close c))))))))
    port))

;;; ---- the CONNECT proxy ------------------------------------------------------------

(defvar *seen* nil "The request header of the most recent CONNECT, as a string.")
(defvar *mode* :ok "How the proxy answers: :OK, :REFUSE (407), or :EARLY (tunnel bytes
   in the same write as the reply header).")

(defun read-header (s)
  "The request header up to the blank line, byte by byte."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop
      (let ((b (read-byte s)))
        (vector-push-extend b out)
        (let ((n (fill-pointer out)))
          (when (and (>= n 4)
                     (= (aref out (- n 4)) 13) (= (aref out (- n 3)) 10)
                     (= (aref out (- n 2)) 13) (= (aref out (- n 1)) 10))
            (return (bytes->string out))))))))

(defun pipe (from to)
  (ignore-errors
   (loop for b = (read-byte from nil nil) while b
         do (write-byte b to) (finish-output to)))
  (ignore-errors (close to)))

(defun start-proxy ()
  (multiple-value-bind (srv port) (listen-loopback)
    (sb-thread:make-thread
     (lambda ()
       (loop
         (multiple-value-bind (c s) (accept-stream srv)
           (sb-thread:make-thread
            (lambda ()
              (ignore-errors
               (let ((header (read-header s)))
                 (setf *seen* header)
                 (ecase *mode*
                   (:refuse
                    (write-sequence (crlf-bytes (format nil "HTTP/1.1 407 Proxy Authentication Required~c~c~c~c"
                                                        #\Return #\Newline #\Return #\Newline)) s)
                    (finish-output s))
                   ((:ok :early)
                    (let* ((line (subseq header 0 (search (coerce '(#\Return #\Newline) 'string) header)))
                           (target (second (let ((parts '()) (start 0))
                                             (loop for i = (position #\Space line :start start)
                                                   do (push (subseq line start i) parts)
                                                      (if i (setf start (1+ i)) (return)))
                                             (nreverse parts))))
                           (colon (position #\: target :from-end t))
                           (host (subseq target 0 colon))
                           (tport (parse-integer target :start (1+ colon)))
                           (up nil)
                           (us (multiple-value-bind (sock stream)
                                   (cl-transport.connect:connect-tcp host tport)
                                 (setf up sock)
                                 stream))
                           (reply (format nil "HTTP/1.1 200 Connection established~c~c~c~c"
                                          #\Return #\Newline #\Return #\Newline)))
                      (if (eq *mode* :early)
                          (write-sequence (crlf-bytes (concatenate 'string reply "EARLY")) s)
                          (write-sequence (crlf-bytes reply) s))
                      (finish-output s)
                      (sb-thread:make-thread (lambda () (pipe us s)))
                      (pipe s us)
                      (ignore-errors (sb-bsd-sockets:socket-close up)))))))
              (ignore-errors (sb-bsd-sockets:socket-close c))))))))
    port))

;;; ---- checks -----------------------------------------------------------------------

(format t "~&== http-connect carrier~%")
(let* ((echo (start-echo))
       (proxy (start-proxy)))
  ;; 1. a tunnel carries bytes both ways
  (multiple-value-bind (s closer)
      (progn (setf *mode* :ok)
        (cl-transport.http-connect:http-connect "127.0.0.1" echo
                                                :proxy-host "127.0.0.1" :proxy-port proxy
                                                :timeout 10))
    (write-sequence (crlf-bytes "ping") s) (finish-output s)
    (let ((got (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence got s)
      (ok "tunnel echoes bytes back through the proxy" (bytes->string got) "ping"))
    ;; 2. the proxy was asked for the target as CONNECT host:port, with a Host header
    (ok "proxy received CONNECT to the target"
        (search (format nil "CONNECT 127.0.0.1:~d HTTP/1.1" echo) *seen*) 0)
    (ok "CONNECT carries the Host header"
        (and (search (format nil "Host: 127.0.0.1:~d" echo) *seen*) t) t)
    (funcall closer))

  ;; 3. Proxy-Authorization goes out when given, and not when not
  (progn (setf *mode* :ok)
    (multiple-value-bind (s closer)
        (cl-transport.http-connect:http-connect "127.0.0.1" echo
                                                :proxy-host "127.0.0.1" :proxy-port proxy
                                                :proxy-authorization "Basic dGVzdDp0ZXN0"
                                                :timeout 10)
      (ok "Proxy-Authorization is sent when configured"
          (and (search "Proxy-Authorization: Basic dGVzdDp0ZXN0" *seen*) t) t)
      (funcall closer)
      (cl-transport.http-connect:http-connect "127.0.0.1" echo
                                              :proxy-host "127.0.0.1" :proxy-port proxy
                                              :timeout 10)
      (ok "Proxy-Authorization is absent when not configured"
          (and (search "Proxy-Authorization" *seen*) t) nil)))

  ;; 4. a refusal is an error that names the status
  (progn (setf *mode* :refuse)
    (ok "a 407 from the proxy signals an error"
        (handler-case (progn (cl-transport.http-connect:http-connect
                              "127.0.0.1" echo :proxy-host "127.0.0.1" :proxy-port proxy
                              :timeout 10)
                             :no-error)
          (error (e) (if (search "407" (princ-to-string e)) :refused-407 (princ-to-string e))))
        :refused-407))

  ;; 5. bytes that share a write with the reply header are the tunnel's, not dropped
  (progn (setf *mode* :early)
    (multiple-value-bind (s closer)
        (cl-transport.http-connect:http-connect "127.0.0.1" echo
                                                :proxy-host "127.0.0.1" :proxy-port proxy
                                                :timeout 10)
      (let ((got (make-array 5 :element-type '(unsigned-byte 8))))
        (read-sequence got s)
        (ok "bytes after the reply header are kept, not read into the header"
            (bytes->string got) "EARLY"))
      (funcall closer)))

  ;; 6. DIAL with the carrier, and its proxy taken from *HTTP-PROXY*
  (ok "transport-available-p knows :http-connect"
      (and (cl-transport:transport-available-p :http-connect) t) t)
  (setf *mode* :ok)
  (let ((cl-transport:*http-proxy* (cons "127.0.0.1" proxy)))
    (multiple-value-bind (s closer)
        (cl-transport:dial "127.0.0.1" echo :transport :http-connect :timeout 10)
      (write-sequence (crlf-bytes "dial") s) (finish-output s)
      (let ((got (make-array 4 :element-type '(unsigned-byte 8))))
        (read-sequence got s)
        (ok "DIAL :http-connect tunnels through *http-proxy*" (bytes->string got) "dial"))
      (funcall closer))))

;; ---- the direct carrier, the timeouts, and EXPOSE ------------------------------------

(format t "~&== direct carrier, timeouts, and inbound~%")
(let ((echo (start-echo)))
  ;; 7. :direct, now on sb-bsd-sockets, carries bytes both ways
  (multiple-value-bind (s closer) (cl-transport:dial "127.0.0.1" echo :transport :direct
                                                      :timeout 10)
    (write-sequence (crlf-bytes "direct") s) (finish-output s)
    (let ((got (make-array 6 :element-type '(unsigned-byte 8))))
      (read-sequence got s)
      (ok ":direct dial carries bytes both ways" (bytes->string got) "direct"))
    (funcall closer))

  ;; 8. the dial timeout bounds the CONNECT, not the stream: a tunnel that is quiet for
  ;; longer than the timeout is still open afterwards
  (multiple-value-bind (s closer) (cl-transport:dial "127.0.0.1" echo :transport :direct
                                                      :timeout 1)
    (sleep 2)
    (write-sequence (crlf-bytes "quiet") s) (finish-output s)
    (let ((got (make-array 5 :element-type '(unsigned-byte 8))))
      (read-sequence got s)
      (ok "a stream quiet past the dial timeout is not cut off" (bytes->string got) "quiet"))
    (funcall closer))

  ;; 9. a connect that cannot finish is an error within its timeout, not a hang
  (let ((started (get-internal-real-time)))
    (ok "a connect past its timeout signals, and does not hang"
        (let ((r (handler-case (progn (cl-transport.connect:connect-tcp "10.255.255.1" 9
                                                                         :timeout 1)
                                      :connected)
                   (error () :failed))))
          (and (member r '(:failed)) (< (- (get-internal-real-time) started)
                                        (* 10 internal-time-units-per-second))
               :failed-in-time))
        :failed-in-time))

  ;; 9b. a refused connect is an error straight away, not a timeout
  (let ((closed (multiple-value-bind (srv p) (listen-loopback)
                  (sb-bsd-sockets:socket-close srv) p)))
    (ok "a refused connect signals at once"
        (handler-case (progn (cl-transport.connect:connect-tcp "127.0.0.1" closed :timeout 5)
                             :connected)
          (error () :refused))
        :refused))

  ;; 10. EXPOSE :tcp hands each connection to the callback, with the peer's address
  (let* ((seen nil)
         (lock (sb-thread:make-mutex))
         (port (multiple-value-bind (srv p) (listen-loopback)
                 (sb-bsd-sockets:socket-close srv)
                 p))
         (closer (cl-transport:expose
                  (lambda (stream peer)
                    (sb-thread:with-mutex (lock) (push peer seen))
                    (write-sequence (crlf-bytes "hello") stream) (finish-output stream))
                  :backend :tcp :host "127.0.0.1" :port port)))
    (unwind-protect
         (multiple-value-bind (sock s) (cl-transport.connect:connect-tcp "127.0.0.1" port
                                                                          :timeout 10)
           (let ((got (make-array 5 :element-type '(unsigned-byte 8))))
             (read-sequence got s)
             (ok "EXPOSE :tcp sends each connection to the callback" (bytes->string got) "hello"))
           (sb-bsd-sockets:socket-close sock))
      (funcall closer))
    (sleep 0.1)
    (let ((peer (sb-thread:with-mutex (lock) (first seen))))
      (ok "the callback is told the peer's address" (getf peer :host) "127.0.0.1")
      (ok "the callback is told the peer's port" (and (integerp (getf peer :port)) t) t))))

(ok "usocket is not loaded: the carriers need nothing beyond SBCL"
    (and (find-package "USOCKET") t) nil)
(ok "bordeaux-threads is not loaded either"
    (and (find-package "BORDEAUX-THREADS") t) nil)
(format t "~&~d passed, ~d failed~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
