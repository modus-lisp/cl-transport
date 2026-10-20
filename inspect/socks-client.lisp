;;;; socks-client.lisp — the :SOCKS5 carrier, and EXPOSE's closer, against a real SOCKS5 server.
;;;;
;;;;   sbcl --script inspect/socks-client.lisp
;;;;
;;;; The SOCKS5 server is a loopback thread that does the RFC 1928 handshake, then either
;;;; tunnels to the target or refuses with a chosen reply code, and records what it was
;;;; asked, so each check is about what crossed the wire.  Nothing beyond SBCL is needed.

(require :asdf)
(require :sb-bsd-sockets)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport")))

(defpackage #:socks-client-test (:use #:cl)) (in-package #:socks-client-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got expect)
  (if (equal got expect)
      (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a~%       got    ~s~%       expect ~s~%" name got expect))))

(defun bytes->string (v) (map 'string #'code-char v))

(defun listen-loopback ()
  (let ((srv (cl-transport.listeners:tcp-listen 0 :address "127.0.0.1")))
    (values srv (nth-value 1 (sb-bsd-sockets:socket-name srv)))))

(defun accept-stream (srv)
  (let ((c (sb-bsd-sockets:socket-accept srv)))
    (values c (sb-bsd-sockets:socket-make-stream c :input t :output t
                                                    :element-type '(unsigned-byte 8)
                                                    :buffering :full))))

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

;;; ---- the SOCKS5 server ------------------------------------------------------------

(defvar *socks-seen* nil "The (name . port) of the most recent SOCKS5 CONNECT, and its atyp.")
(defvar *socks-refuse* nil "When non-NIL, the REP code the server answers the request with.")

(defun read-exact (s n)
  (let ((b (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n b) (setf (aref b i) (read-byte s)))))

(defun reply (s rep)
  "A SOCKS5 reply with REP and a zero bound address."
  (write-sequence (make-array 10 :element-type '(unsigned-byte 8)
                                 :initial-contents (list 5 rep 0 1 0 0 0 0 0 0))
                  s)
  (finish-output s))

(defun serve-socks (c s)
  (ignore-errors
   ;; greeting: version 5, the methods offered; answer no-auth
   (let ((greet (read-exact s 2)))
     (read-exact s (aref greet 1))
     (write-sequence #(5 0) s) (finish-output s))
   ;; request: ver, cmd, rsv, atyp, address, port
   (let* ((hdr (read-exact s 4)) (atyp (aref hdr 3))
          (name (ecase atyp
                  (3 (let ((n (aref (read-exact s 1) 0)))
                       (bytes->string (read-exact s n))))
                  (1 (format nil "~{~d~^.~}" (coerce (read-exact s 4) 'list)))))
          (port (let ((p (read-exact s 2))) (+ (* 256 (aref p 0)) (aref p 1)))))
     (setf *socks-seen* (list name port atyp))
     (cond
       (*socks-refuse* (reply s *socks-refuse*))
       (t
        (multiple-value-bind (up-sock up) (cl-transport.connect:connect-tcp name port)
          (declare (ignore up-sock))
          (reply s 0)
          (sb-thread:make-thread
           (lambda ()
             (ignore-errors
              (loop for b = (read-byte up nil nil) while b do (write-byte b s) (finish-output s)))))
          (ignore-errors
           (loop for b = (read-byte s nil nil) while b do (write-byte b up) (finish-output up)))))))
   (ignore-errors (sb-bsd-sockets:socket-close c))))

(defun start-socks ()
  (multiple-value-bind (srv port) (listen-loopback)
    (sb-thread:make-thread
     (lambda ()
       (loop
         (multiple-value-bind (c s) (accept-stream srv)
           (sb-thread:make-thread (lambda () (serve-socks c s)))))))
    port))

(defun echo-through (stream text)
  (let* ((bytes (map '(vector (unsigned-byte 8)) #'char-code text))
         (got (make-array (length bytes) :element-type '(unsigned-byte 8))))
    (write-sequence bytes stream) (finish-output stream)
    (read-sequence got stream)
    (bytes->string got)))

;;; ---- checks -----------------------------------------------------------------------

(format t "~&== :socks5 carrier and EXPOSE's closer~%")
(let* ((echo (start-echo))
       (socks (start-socks)))
  ;; 1. a tunnel through the proxy carries bytes both ways
  (multiple-value-bind (s closer)
      (cl-transport.socks:socks5-connect "127.0.0.1" echo :proxy-host "127.0.0.1"
                                                          :proxy-port socks :timeout 10)
    (ok "SOCKS5 tunnel echoes bytes back" (echo-through s "socks") "socks")
    (funcall closer))

  ;; 2. the hostname goes to the proxy as a name (atyp 3), so the proxy resolves it
  (ok "the target is sent as a domain name (atyp 3)"
      (third *socks-seen*) 3)
  (ok "the target name and port are what was asked for"
      (list (first *socks-seen*) (second *socks-seen*)) (list "127.0.0.1" echo))

  ;; 3. a refused CONNECT signals, and names the reply
  (setf *socks-refuse* 5)
  (progn
    (ok "a SOCKS5 refusal (rep 5) signals an error that names it"
        (handler-case (progn (cl-transport.socks:socks5-connect "127.0.0.1" echo
                                                                :proxy-host "127.0.0.1"
                                                                :proxy-port socks :timeout 10)
                             :connected)
          (error (e) (if (search "rep 5" (princ-to-string e)) :refused-rep-5 :other)))
        :refused-rep-5))
  (setf *socks-refuse* nil)

  ;; 4. DIAL :socks5 uses the :proxy it is given, and *socks-proxy* when it is not
  (multiple-value-bind (s closer)
      (cl-transport:dial "127.0.0.1" echo :transport :socks5 :timeout 10
                                          :proxy (cons "127.0.0.1" socks))
    (ok "DIAL :socks5 tunnels through the :proxy argument" (echo-through s "dial") "dial")
    (funcall closer))
  (let ((cl-transport:*socks-proxy* (cons "127.0.0.1" socks)))
    (multiple-value-bind (s closer)
        (cl-transport:dial "127.0.0.1" echo :transport :socks5 :timeout 10)
      (ok "DIAL :socks5 falls back to *socks-proxy*" (echo-through s "dflt") "dflt")
      (funcall closer)))

  ;; 5. EXPOSE's closer stops accepting: open before it, refused after it
  (let* ((port (multiple-value-bind (srv p) (listen-loopback)
                 (sb-bsd-sockets:socket-close srv) p))
         (closer (cl-transport:expose (lambda (stream peer) (declare (ignore peer))
                                        (write-sequence #(104 105) stream) (finish-output stream))
                                      :backend :tcp :host "127.0.0.1" :port port)))
    (ok "EXPOSE listens before its closer runs"
        (handler-case (multiple-value-bind (sock s)
                          (cl-transport.connect:connect-tcp "127.0.0.1" port :timeout 5)
                        (declare (ignore s))
                        (sb-bsd-sockets:socket-close sock) :open)
          (error () :refused))
        :open)
    (funcall closer)
    (sleep 0.1)
    (ok "after EXPOSE's closer, the listener refuses"
        (handler-case (progn (cl-transport.connect:connect-tcp "127.0.0.1" port :timeout 2) :open)
          (error () :refused))
        :refused)))

(format t "~&~d passed, ~d failed~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
