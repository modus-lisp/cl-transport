;;;; transport-gate.lisp — the gate does what it says.
;;;;
;;;;   sbcl --script inspect/transport-gate.lisp
;;;;
;;;; No network is required for the checks that matter: a DENY is proved by the
;;;; connection never being attempted, and the one test that does reach out is
;;;; skipped when there is nothing to reach.

(require :asdf)
(let ((ql (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (probe-file ql) (load ql)))
;; This directory only, the way the other suites find the system: it needs nothing else,
;; and a tree scan of the workspace can find an older copy of cl-transport vendored
;; somewhere else first.  (modus's ASDF also has no INITIALIZE-SOURCE-REGISTRY.)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system :cl-transport)))

(defpackage #:transport-gate-test (:use #:cl)) (in-package #:transport-gate-test)

(defvar *pass* 0) (defvar *fail* 0) (defvar *skip* 0)
(defun ok (name got &optional detail)
  (if got (progn (incf *pass*) (format t "  [pass] ~a~@[ — ~a~]~%" name detail))
      (progn (incf *fail*) (format t "  [FAIL] ~a~@[ — ~a~]~%" name detail)))
  (finish-output) got)
(defun skip (name why) (incf *skip*) (format t "  [skip] ~a — ~a~%" name why) (finish-output))
(defun head (s) (format t "~%== ~a ==~%" s) (finish-output))

(defun %lines (s)
  (loop with start = 0 for nl = (position #\Newline s :start start)
        collect (subseq s start (or nl (length s)))
        while nl do (setf start (1+ nl))))

(defun connect (addr port)
  "Attempt a connection; return :OK, or the condition."
  (handler-case
      (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
        (unwind-protect (progn (sb-bsd-sockets:socket-connect s addr port) :ok)
          (ignore-errors (sb-bsd-sockets:socket-close s))))
    (condition (c) c)))

;; Every check below that is not ABOUT carriers runs as though something dialled,
;; because the default is now :RAW and :RAW satisfies no requirement.
(setf cl-transport.gate:*carrier* :direct)
;; NO NETWORK IS USED.  Every connection below goes to 127.0.0.1:9, which refuses
;; immediately, with the loopback exemption turned off so the policy still applies to
;; it -- a gate test that dialled a real host would be timing the internet rather than
;; testing the gate, and would fail on a train.
(setf cl-transport.gate:*allow-loopback* nil)
(defparameter +nowhere+ #(127 0 0 1))
(defparameter +noport+ 9)

(head "globbing")
(ok "* matches anything"        (cl-transport.gate::glob-match-p "*" "anything"))
(ok "a prefix glob"             (cl-transport.gate::glob-match-p "loom/*" "loom/browser"))
(ok "…and rejects a non-match"  (not (cl-transport.gate::glob-match-p "loom/*" "spool/feed")))
(ok "an infix glob"             (cl-transport.gate::glob-match-p "*.ycombinator.com" "news.ycombinator.com"))
(ok "case-insensitive"          (cl-transport.gate::glob-match-p "EXAMPLE.com" "example.COM"))
(ok "a literal is exact"        (not (cl-transport.gate::glob-match-p "example.com" "notexample.com")))

(head "the policy document")
(let ((path (format nil "/tmp/transport-gate-~d.conf" (sb-posix:getpid))))
  (with-open-file (o path :direction :output :if-exists :supersede)
    (format o "# a policy~%default deny~%~%allow  loom/*   93.184.216.34:443~%~
               deny   *        *:25~%allow  browser  *:443~%allow  10.0.0.1~%"))
  (let ((n (cl-transport.gate:load-policy path)))
    (ok "every rule is read" (= n 4) (format nil "~d rules" n)))
  (ok "`default deny' is taken" (eq cl-transport.gate:*default-action* :deny))
  (ok "a principal-less rule means anybody"
      (eq (cl-transport.gate:decide "whoever" "10.0.0.1" 80) :allow))
  (ok "a rule matches its principal"
      (eq (cl-transport.gate:decide "loom/browser" "93.184.216.34" 443) :allow))
  (ok "…and not another one"
      (eq (cl-transport.gate:decide "spool/feed" "93.184.216.34" 443) :deny))
  (ok "first match wins: the deny above the allow"
      (eq (cl-transport.gate:decide "browser" "1.2.3.4" 25) :deny))
  (ok "…and the allow below it still applies"
      (eq (cl-transport.gate:decide "browser" "1.2.3.4" 443) :allow))
  (ok "an unmatched connection takes the default"
      (eq (cl-transport.gate:decide "browser" "1.2.3.4" 8080) :deny))
  (ok "loopback is exempt when that is left on"
      (let ((cl-transport.gate:*allow-loopback* t))
        (eq (cl-transport.gate:decide "anyone" "127.0.0.1" 9999) :allow)))
  ;; A rule that cannot be parsed must stop the load, not be skipped quietly.
  (with-open-file (o path :direction :output :if-exists :supersede)
    (format o "allow loom/* example.com~%wibble~%"))
  (ok "an unparsable line is an error, not a shrug"
      (handler-case (progn (cl-transport.gate:load-policy path) nil) (error () t)))
  (ignore-errors (delete-file path)))

(head "names are learned from the resolver, so rules can use them")
(cl-transport.gate:clear-policy)
(setf cl-transport.gate:*default-action* :allow)
(cl-transport.gate:arm)
(ok "armed" (cl-transport.gate:armed-p))
(cl-transport.gate::note-name #(93 184 216 34) "example.com")
(ok "an address remembers its name"
    (member "example.com" (cl-transport.gate::names-for "93.184.216.34") :test #'string=))
(cl-transport.gate:add-rule :deny "*" "example.com" "*" "test")
(ok "a rule by NAME decides a connection made by ADDRESS"
    (eq (cl-transport.gate:decide "anybody" "93.184.216.34" 443) :deny))

(head "the gate stops a connection")
;; The rule above names example.com; this one has to bite on the address actually
;; dialled, so the loopback the test uses is denied by name too -- the same
;; name-to-address join, exercised through a real connect rather than through DECIDE.
(cl-transport.gate::note-name +nowhere+ "nowhere.test")
(cl-transport.gate:add-rule :deny "*" "nowhere.test" "*" "test")
(cl-transport.gate:clear-connections)
(let ((r (cl-transport.gate::with-principal ("spool/feed") (connect +nowhere+ +noport+))))
  (ok "a denied connect signals BLOCKED" (typep r 'cl-transport.gate:blocked)
      (and (typep r 'condition) (princ-to-string r)))
  ;; The point of it being a plain ERROR: existing callers already catch that.
  (ok "…which is an ERROR, so existing handlers catch it" (typep r 'error)))
(let ((rec (first (cl-transport.gate:connections))))
  (ok "the attempt is recorded" rec)
  (when rec
    (ok "…against the principal that made it"
        (string= (cl-transport.gate:connection-principal rec) "spool/feed")
        (cl-transport.gate:connection-principal rec))
    (ok "…with the verdict" (eq (cl-transport.gate:connection-action rec) :deny))
    ;; HOW it travelled, not only where to.  Without this the log cannot answer the
    ;; question somebody asks just before turning on `require * via cl-transport':
    ;; what is still opening its own sockets?
    (ok "…and the carrier it travelled over"
        (eq (cl-transport.gate:connection-carrier rec) :direct)
        (princ-to-string (cl-transport.gate:connection-carrier rec)))))

;; A raw connection records itself as raw, which is the line a migration is read from.
(let ((cl-transport.gate:*carrier* :raw))
  (cl-transport.gate:clear-connections)
  (cl-transport.gate::with-principal ("undialled") (connect +nowhere+ +noport+))
  (let ((rec (first (cl-transport.gate:connections))))
    (ok "a connection nobody dialled is recorded as :raw"
        (and rec (eq (cl-transport.gate:connection-carrier rec) :raw)))))

;; And the report says `deny' the same way it says `allow' — one shape, so a reader
;; scans the column rather than the capitalisation.
(let ((text (with-output-to-string (o) (cl-transport.gate:report :stream o :limit 5))))
  (ok "the report is lowercase throughout, and names the carrier"
      (and (search "via " text) (not (search "DENY" text)))
      (string-right-trim '(#\Newline) (or (second (%lines text)) ""))))

(head "the record is readable, not only printable")
;; REPORT prints; CONNECTIONS is the data behind it.  Over a control socket the objects
;; are opaque, so :PLIST is what a caller on the far end of `kiln eval' actually gets.
(let* ((pl (first (cl-transport.gate:connections :limit 1 :as :plist))))
  (ok "…as a plist" (and (listp pl) (getf pl :principal))
      (princ-to-string (getf pl :principal)))
  (ok "…naming the carrier and the verdict"
      (and (getf pl :carrier) (getf pl :action)))
  (ok "…and where the decision came from, as text rather than an object"
      (or (null (getf pl :source)) (stringp (getf pl :source))))
  ;; The whole point: it survives a round trip through a socket, which an object does not.
  (ok "…and reads back after being printed"
      (let ((again (read-from-string (prin1-to-string pl))))
        (equal (getf again :principal) (getf pl :principal)))))

(head "the principal defaults to the thread")
(cl-transport.gate:clear-connections)
(let ((th (sb-thread:make-thread (lambda () (connect +nowhere+ +noport+))
                                 :name "a-named-thread")))
  (sb-thread:join-thread th :default nil))
(let ((rec (first (cl-transport.gate:connections))))
  (ok "an unnamed caller is attributed to its thread"
      (and rec (string= (cl-transport.gate:connection-principal rec) "a-named-thread"))
      (and rec (cl-transport.gate:connection-principal rec))))

(head "and it catches code that does not know it exists")
;; usocket is third-party and was never edited: this is the whole claim of the design.
(if (handler-case (progn (funcall (read-from-string "ql:quickload") :usocket :silent t) t)
      (error () nil))
    (progn
      (cl-transport.gate:clear-policy) (cl-transport.gate:clear-connections)
      (cl-transport.gate:add-rule :deny "*" "*" "*" "gate")
      (let ((r (handler-case (funcall (read-from-string "usocket:socket-connect")
                                      "93.184.216.34" 443)
                 (condition (c) c))))
        (ok "a usocket connection is gated too" (typep r 'cl-transport.gate:blocked)
            (princ-to-string r))))
    (skip "usocket" "not installed"))

(head "must use cl-transport")
;; The point of :RAW.  A policy can demand that the machine's networking go through
;; the one place that knows how to route it, BEFORE demanding anything about where.
(cl-transport.gate:clear-policy)
(setf cl-transport.gate:*default-action* :allow)
(let ((path (format nil "/tmp/transport-gate-via-~d.conf" (sb-posix:getpid))))
  (with-open-file (o path :direction :output :if-exists :supersede)
    (format o "require *  via cl-transport~%"))
  (cl-transport.gate:load-policy path)
  (ignore-errors (delete-file path)))
(let ((cl-transport.gate:*carrier* :raw))
  (ok "a socket nobody dialled is refused"
      (typep (connect +nowhere+ +noport+) 'cl-transport.gate:blocked)))
(let ((cl-transport.gate:*carrier* :direct))
  (ok "…and the same socket is fine once it has been dialled"
      (not (typep (connect +nowhere+ +noport+) 'cl-transport.gate:blocked))))

(head "and a carrier can be required by name")
(cl-transport.gate:clear-policy)
(cl-transport.gate:require-carrier "loom/*" :tor "test")
(let ((cl-transport.gate:*carrier* :direct))
  (ok "the browser going direct is refused when Tor is required"
      (typep (cl-transport.gate::with-principal ("loom/browser") (connect +nowhere+ +noport+))
             'cl-transport.gate:blocked)))
(let ((cl-transport.gate:*carrier* :tor))
  (ok "…and allowed over Tor"
      (not (typep (cl-transport.gate::with-principal ("loom/browser") (connect +nowhere+ +noport+))
                  'cl-transport.gate:blocked))))
(let ((cl-transport.gate:*carrier* :raw))
  (ok "…while another principal is unaffected by loom's requirement"
      (not (typep (cl-transport.gate::with-principal ("spool/feed") (connect +nowhere+ +noport+))
                  'cl-transport.gate:blocked))))

(head "DIAL declares the carrier itself")
(cl-transport.gate:clear-policy)
(cl-transport.gate:require-carrier "*" :any "test")
;; No hook involved: DIAL binds *CARRIER* around the connection it makes, so
;; a dialled connection satisfies `via any' and a hand-rolled socket does not.
(ok "a dialled connection satisfies `via any'"
    (let ((r (handler-case (multiple-value-bind (s closer)
                               (cl-transport:dial "127.0.0.1" 9 :transport :direct :timeout 2)
                             (declare (ignore s)) (funcall closer) :ok)
               (cl-transport.gate:blocked (c) c)
               (error () :ok))))                    ; refused by the network, not the gate
      (not (typep r 'cl-transport.gate:blocked))))
(ok "…and an undialled one does not"
    (let ((cl-transport.gate:*carrier* :raw))
      (typep (connect +nowhere+ +noport+) 'cl-transport.gate:blocked)))

(head "UDP is gated too")
;; The largest hole in the first cut: ICE and TURN never connect, they send datagrams
;; with the destination on each SEND, so a gate watching only CONNECT saw none of it.
(cl-transport.gate:clear-policy)
(setf cl-transport.gate:*default-action* :deny)
(let* ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
       (r (handler-case
              (progn (sb-bsd-sockets:socket-send s (make-array 4 :element-type '(unsigned-byte 8))
                                                 4 :address (list +nowhere+ 3478))
                     :sent)
            (condition (c) c))))
  (ignore-errors (sb-bsd-sockets:socket-close s))
  (ok "a datagram to a denied destination is refused"
      (typep r 'cl-transport.gate:blocked) (princ-to-string r)))
(setf cl-transport.gate:*default-action* :allow)

(head "disarming puts things back")
(cl-transport.gate:disarm)
(ok "disarmed" (not (cl-transport.gate:armed-p)))
(cl-transport.gate:clear-policy) (setf cl-transport.gate:*default-action* :allow)
(let ((r (connect #(127 0 0 1) 1)))
  (ok "a connect after disarm is the socket's own business again"
      (not (typep r 'cl-transport.gate:blocked))
      (if (eq r :ok) "connected" (princ-to-string r))))

(format t "~%~d passed, ~d failed, ~d skipped~%~%=> ~:[FAIL~;PASS~]~%"
        *pass* *fail* *skip* (zerop *fail*))
(finish-output)
(sb-ext:exit :code (if (plusp *fail*) 1 0))
