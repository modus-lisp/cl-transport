;;;; sockets.lisp — cl-transport/sockets on real loopback sockets, SBCL or modus.
;;;;
;;;;   sbcl --script inspect/sockets.lisp
;;;;   modus --script inspect/sockets.lisp
;;;;
;;;; One file for both: it uses nothing but the system under test and ANSI CL, so a
;;;; difference between the two Lisps shows up as a failure here.  Every socket is
;;;; 127.0.0.1 on an ephemeral port.

(require :asdf)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport/sockets")))

(defpackage #:sockets-test (:use #:cl #:cl-transport.sockets)) (in-package #:sockets-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got &optional detail)
  (if got (progn (incf *pass*) (format t "  [pass] ~a~@[ — ~a~]~%" name detail))
      (progn (incf *fail*) (format t "  [FAIL] ~a~@[ — ~a~]~%" name detail)))
  (finish-output) got)
(defun head (s) (format t "~%== ~a ==~%" s) (finish-output))
(defun v (&rest xs) (coerce xs '(simple-array (unsigned-byte 8) (*))))
(defun deadline (ms) (+ (get-internal-real-time) (round (* ms internal-time-units-per-second) 1000)))

(head "addresses")
(ok "a dotted quad parses" (equalp (dotted-quad "10.0.200.7") #(10 0 200 7)))
(ok "a bad one does not" (and (null (dotted-quad "10.0.256.7")) (null (dotted-quad "a.b.c.d"))))
(ok "a host string resolves" (equalp (resolve-host "127.0.0.1") #(127 0 0 1)))

(head "UDP: one socket, many peers")
(let* ((admit-first-byte-7 (lambda (d) (and (plusp (length d)) (= (aref d 0) 7))))
       (a (udp-open :admit admit-first-byte-7))
       (b (udp-open)) (c (udp-open)))
  (unwind-protect
       (let ((pa (udp-local-port a)))
         (ok "bound to ephemeral ports" (and (plusp pa) (/= pa (udp-local-port b))))
         ;; B and C both talk to A; A holds a handle for B only
         (let ((ab (udp-peer-handle a "127.0.0.1" (udp-local-port b))))
           (udp-send b "127.0.0.1" pa (v 1 1))
           (udp-send c "127.0.0.1" pa (v 9 9))          ; a stranger, not admitted
           (udp-send c "127.0.0.1" pa (v 7 7))          ; a stranger, admitted
           (multiple-value-bind (d status) (udp-peer-read ab (deadline 1000))
             (ok "B's datagram reaches B's handle" (and (eq status :ok) (equalp d (v 1 1)))))
           (udp-pump a :timeout-ms 200)
           (ok "a stranger the predicate refuses is dropped" (= (udp-endpoint-dropped a) 1))
           (multiple-value-bind (cp host port) (udp-accept a :timeout-ms 500)
             (ok "the admitted stranger is offered, with its sender"
                 (and cp (equal host "127.0.0.1") (= port (udp-local-port c))))
             (when cp
               (ok "... its datagram queued on the new handle"
                   (equalp (udp-peer-read cp (deadline 100)) (v 7 7)))
               (let ((ca (udp-peer-handle c "127.0.0.1" pa)))
                 (udp-peer-write cp (v 3 3 3))
                 (ok "a handle writes back to its peer"
                     (equalp (udp-peer-read ca (deadline 1000)) (v 3 3 3))))))
           (multiple-value-bind (d status) (udp-peer-read ab (deadline 100))
             (ok "an empty handle times out" (and (eq status :timeout) (zerop (length d)))))
           (ok "a second handle for the same address is refused"
               (handler-case (progn (udp-peer-handle a "127.0.0.1" (udp-local-port b)) nil) (error () t)))
           (udp-peer-close ab)
           (ok "closing a handle forgets it" (handler-case (progn (udp-peer-handle a "127.0.0.1" (udp-local-port b)) t)
                                               (error () nil)))))
    (udp-close a) (udp-close b) (udp-close c)))

(head "TCP: buffered sockets, deadline reads")
(let ((l (tcp-listen)))
  (unwind-protect
       (let* ((client (tcp-connect "127.0.0.1" (tcp-listener-port l)))
              (server (tcp-accept l :timeout-ms 1000)))
         (ok "connect and accept" (and client server))
         (ok "an idle socket is not readable" (null (wait-readable (list server) 100)))
         (tcp-write client (v 1 2 3 4 5 6))
         (ok "written bytes make it readable" (equal (wait-readable (list server) 1000) (list server)))
         (multiple-value-bind (d status) (tcp-read-exactly server 4 (deadline 1000))
           (ok "an exact read returns exactly that" (and (eq status :ok) (equalp d (v 1 2 3 4)))))
         (ok "the rest stays buffered, and counts as readable"
             (and (tcp-buffered-p server) (equal (wait-readable (list server) 0) (list server))))
         (multiple-value-bind (d status) (tcp-read-exactly server 4 (deadline 200))
           (ok "a read that cannot finish times out with what came" (and (eq status :timeout) (equalp d (v 5 6)))))
         (tcp-write server (v 9))
         (ok "the other way" (equalp (progn (wait-readable (list client) 1000) (tcp-read-available client)) (v 9)))
         (tcp-shutdown-output client)
         (multiple-value-bind (d eof) (progn (wait-readable (list server) 1000) (tcp-read-available server))
           (ok "a half-close reads as end of stream" (and eof (zerop (length d)))))
         (tcp-close client) (tcp-close server)
         (ok "a refused connect signals"
             (handler-case (let ((p (tcp-listener-port l))) (tcp-listener-close l) (tcp-connect "127.0.0.1" p) nil)
               (error () t))))
    (tcp-listener-close l)))

(head "waiting on TCP and UDP together")
(let* ((u (udp-open)) (l (tcp-listen)) (t0 (get-internal-real-time)))
  (unwind-protect
       (let ((sender (udp-open)))
         (udp-send sender "127.0.0.1" (udp-local-port u) (v 1))
         (wait-readable (list l) 2000 :udp u)
         (ok "UDP input ends a wait on TCP sockets promptly"
             (< (- (get-internal-real-time) t0) (* 1/2 internal-time-units-per-second)))
         (udp-close sender))
    (udp-close u) (tcp-listener-close l)))

(format t "~%~d passed, ~d failed~%" *pass* *fail*)
(finish-output)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
