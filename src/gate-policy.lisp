;;;; policy.lisp — the rules, and the document they are read from.
;;;;
;;;; The file is line-oriented with `#' comments, which is the shape kiln's profiles
;;;; already use: a config document should be something you can read, diff and paste
;;;; into a message, and an s-expression policy would have been more natural to write
;;;; here and worse to live with.
;;;;
;;;;   default deny                              # the verdict when nothing matches
;;;;   allow  loom/*      news.ycombinator.com   # any port
;;;;   allow  *           *:443                  # https anywhere
;;;;   deny   *           *:25                   # nothing sends mail
;;;;
;;;; FIRST MATCH WINS, top to bottom, so the file reads as a sequence of decisions
;;;; rather than a set of constraints whose interaction has to be worked out.  It is
;;;; the ordering every firewall config in the world already uses, and the one people
;;;; expect when they put a specific line above a general one.

(in-package #:cl-transport.gate)

(defvar *default-action* :allow
  "What DECIDE returns when no rule matches.  :ALLOW by default, deliberately: a gate
   that starts closed would strand the desktop the moment it is armed, and the first
   honest use of this is to watch rather than to stop.  A policy file that says
   `default deny' has made an informed choice; an unconfigured image has not.")

(defvar *carrier* :raw
  "How the bytes about to leave are travelling.  :RAW is the default and means NOBODY
   DIALLED THIS -- some code reached the socket layer directly, without saying how it
   wanted to travel.  DIAL binds this to the transport it is using (:direct, :socks5,
   :tor, ...) for the extent of the connection.

   That default is the whole trick.  `require * via any\' then reads as MUST USE
   CL-TRANSPORT: anything that opened its own socket is carrying :RAW, matches no
   carrier, and is refused.  A policy can demand that the machine\'s networking go
   through the one place that knows how to route it, before demanding anything about
   where it goes.")

(defvar *allow-loopback* t
  "Let connections to the loopback interface through without consulting the rules.
   The desktop's own control socket, its VNC seats and the local viewer all talk over
   127.0.0.1, and a policy written to keep the machine off the internet should not
   have to remember to keep it talking to itself.")

(defclass rule ()
  ((action    :initarg :action    :initform :allow :reader rule-action)
   (principal :initarg :principal :initform "*"    :reader rule-principal)
   (host      :initarg :host      :initform "*"    :reader rule-host)
   (port      :initarg :port      :initform "*"    :reader rule-port)
   (source    :initarg :source    :initform ""     :reader rule-source)))

(defun %make-rule (&key (action :allow) (principal "*") (host "*") (port "*") (source ""))
  (make-instance 'rule :action action :principal principal :host host
                       :port (princ-to-string port) :source source))


;;; CLASSES RATHER THAN STRUCTS, throughout the gate.  These are long-lived objects in
;;; an image that gets code reloaded into it while it runs -- a desktop that has been
;;; up for a week is the normal case, not the exceptional one -- and DEFSTRUCT makes
;;; that a hard stop: adding one slot signals "attempt to redefine the STRUCTURE-OBJECT
;;; class incompatibly", and the only way through is to drop the class and every live
;;; instance with it.  CLOS was built for this; a redefined class updates its instances
;;; instead of refusing to exist.  Measured the hard way: adding the carrier slot below
;;; could not be loaded into the running desktop until the record was thrown away.

(defclass requirement ()
  ((principal :initarg :principal :initform "*"     :reader requirement-principal)
   (carrier   :initarg :carrier   :initform :direct :reader requirement-carrier)
   (source    :initarg :source    :initform ""      :reader requirement-source)))

(defun %make-requirement (&key (principal "*") (carrier :direct) (source ""))
  (make-instance 'requirement :principal principal :carrier carrier :source source))

(defvar *rules* '() "The policy, in order.  First match wins.")
(defvar *requirements* '()
  "Carrier requirements.  Checked BEFORE the allow/deny list, because they are a
   different kind of statement: a rule says whether a destination is permitted, a
   requirement says how the bytes are permitted to travel, and a machine that may
   reach a host over Tor and not directly needs both answers to be separate.")
(defvar *rules-lock* (sb-thread:make-mutex :name "gate-rules"))
(defvar *policy-generation* 0
  "Bumped on every policy change, so caches built from it can tell they are stale.")

(defun policy-rules () (sb-thread:with-mutex (*rules-lock*) (copy-list *rules*)))
(defun policy-requirements () (sb-thread:with-mutex (*rules-lock*) (copy-list *requirements*)))
(defun clear-policy ()
  (sb-thread:with-mutex (*rules-lock*)
    (setf *rules* '() *requirements* '()) (incf *policy-generation*))
  t)

(defun require-carrier (principal carrier &optional (source ""))
  "PRINCIPAL may only reach the network through CARRIER."
  (let ((r (%make-requirement :principal principal :carrier carrier :source source)))
    (sb-thread:with-mutex (*rules-lock*)
      (setf *requirements* (append *requirements* (list r)))
      (incf *policy-generation*))
    r))

(defun add-rule (action principal host &optional (port "*") (source ""))
  "Append a rule.  ACTION is :ALLOW or :DENY; the rest are globs."
  (let ((r (%make-rule :action action :principal principal :host host
                       :port (princ-to-string port) :source source)))
    (sb-thread:with-mutex (*rules-lock*)
      (setf *rules* (append *rules* (list r))) (incf *policy-generation*))
    r))

;;; ---- globbing ---------------------------------------------------------------

(defun glob-match-p (pattern string)
  "Does PATTERN match STRING?  `*' matches any run of characters, including none.
   Case-insensitive, because hostnames are and principals may as well be."
  (let ((p (or pattern "*")) (s (or string "")))
    (labels ((walk (pp ss)
               (cond ((= pp (length p)) (= ss (length s)))
                     ((char= (char p pp) #\*)
                      ;; Try every split; patterns here are short and connections rare,
                      ;; so the naive backtrack is the right amount of machinery.
                      (loop for k from ss to (length s)
                            thereis (walk (1+ pp) k)))
                     ((and (< ss (length s))
                           (char-equal (char p pp) (char s ss)))
                      (walk (1+ pp) (1+ ss)))
                     (t nil))))
      (walk 0 0))))

(defun loopback-p (address-string)
  (let ((s (or address-string "")))
    (or (and (>= (length s) 4) (string= "127." (subseq s 0 4)))
        (string= s "::1")
        (string= s "0:0:0:0:0:0:0:1"))))

(defun %host-matches-p (glob address-string names)
  "A host glob matches the ADDRESS or ANY name that address has been resolved from."
  (or (glob-match-p glob address-string)
      (some (lambda (n) (glob-match-p glob n)) names)))

(defun carrier-violation (principal carrier)
  "The requirement PRINCIPAL is breaking by travelling over CARRIER, or NIL.

   THIS IS WHAT MAKES `via tor' MEAN ANYTHING.  A carrier can be asked for at the
   point a connection is dialled, but asking is advice: the code that would rather
   open its own socket simply does, and a policy expressed only where carriers are
   chosen governs only the callers that already agreed to be governed.  Enforcing it
   down here inverts that -- a principal required to use Tor is refused when it
   reaches the socket by any other road, so the requirement holds over code that has
   never heard of cl-transport."
  (dolist (req (policy-requirements) nil)
    (when (and (glob-match-p (requirement-principal req) principal)
               (not (carrier-satisfies-p carrier (requirement-carrier req))))
      (return req))))

(defun carrier-satisfies-p (carrier required)
  "Does travelling over CARRIER satisfy a requirement for REQUIRED?
   :ANY means any real carrier -- that is, anything that went through DIAL at all,
   which is every value except the :RAW of a socket nobody dialled."
  (if (eq required :any)
      (not (eq carrier :raw))
      (eq carrier required)))

(defun decide (principal address-string port &optional names (carrier *carrier*))
  "Decide what to do about PRINCIPAL connecting to ADDRESS-STRING:PORT over CARRIER.
   Returns (values :ALLOW-or-:DENY rule-or-requirement-or-NIL)."
  (if (and *allow-loopback* (loopback-p address-string))
      (values :allow nil)
      (let ((violated (carrier-violation principal carrier)))
        (if violated
            (values :deny violated)
            (let ((ns (or names (names-for address-string)))
                  (ps (princ-to-string port)))
              (dolist (r (policy-rules) (values *default-action* nil))
                (when (and (glob-match-p (rule-principal r) principal)
                           (%host-matches-p (rule-host r) address-string ns)
                           (glob-match-p (rule-port r) ps))
                  (return (values (rule-action r) r)))))))))

(defun decision-source (thing)
  "Where a verdict came from, for the log and the error message."
  (typecase thing
    (rule (rule-source thing))
    (requirement (format nil "~a; via ~(~a~)" (requirement-source thing)
                         (requirement-carrier thing)))
    ;; A record a worker sent across a channel carries the source as text already.
    (string thing)
    (t nil)))

;;; ---- the document -----------------------------------------------------------

(defun %split-dest (token)
  "\"host:port\" -> (values host port); \"host\" -> (values host \"*\").
   Split on the LAST colon so an IPv6 literal keeps its own."
  (let ((c (position #\: token :from-end t)))
    (if (and c (< (1+ c) (length token))
             (every (lambda (ch) (or (digit-char-p ch) (char= ch #\*)))
                    (subseq token (1+ c))))
        (values (subseq token 0 c) (subseq token (1+ c)))
        (values token "*"))))

(defun %tokens (line)
  (let ((out '()) (start nil))
    (dotimes (i (length line) (progn (when start (push (subseq line start) out))
                                     (nreverse out)))
      (let ((ws (member (char line i) '(#\Space #\Tab))))
        (cond ((and ws start) (push (subseq line start i) out) (setf start nil))
              ((not (or ws start)) (setf start i)))))))

(defun load-policy (path &key (replace t))
  "Read a policy document.  Returns the number of rules read.  Signals on a line it
   cannot parse -- a firewall that silently ignores a rule it did not understand is
   worse than one that refuses to start, because the rule looks present and is not."
  (let ((rules '()) (reqs '()) (default nil) (n 0))
    (with-open-file (in path :if-does-not-exist :error)
      (loop for raw = (read-line in nil nil) for lineno from 1 while raw do
        (let* ((no-comment (let ((h (position #\# raw))) (if h (subseq raw 0 h) raw)))
               (toks (%tokens no-comment)))
          (when toks
            (let ((head (string-downcase (first toks))))
              (cond
                ((string= head "default")
                 (unless (= (length toks) 2)
                   (error "cl-transport: ~a:~d: `default' takes one word (allow or deny)" path lineno))
                 (setf default (%action (second toks) path lineno)))
                ;; require <principal> via <carrier>
                ((string= head "require")
                 (unless (and (= (length toks) 4)
                              (string-equal (third toks) "via"))
                   (error "cl-transport: ~a:~d: expected `require <principal> via <carrier>'"
                          path lineno))
                 (push (%make-requirement
                        :principal (second toks)
                        :carrier (let ((w (string-downcase (fourth toks))))
                                   ;; `via cl-transport\' is how somebody will write
                                   ;; "must be dialled"; it means the same as `any\'.
                                   (if (or (string= w "any") (string= w "cl-transport"))
                                       :any
                                       (intern (string-upcase w) :keyword)))
                        :source (format nil "~a:~d" path lineno))
                       reqs)
                 (incf n))
                ((or (string= head "allow") (string= head "deny"))
                 (unless (member (length toks) '(2 3))
                   (error "cl-transport: ~a:~d: expected `~a <principal> <host[:port]>'"
                          path lineno head))
                 ;; Two tokens means the principal was left out: `allow example.com'
                 ;; reads naturally and means anybody.
                 (let* ((who  (if (= (length toks) 3) (second toks) "*"))
                        (dest (if (= (length toks) 3) (third toks) (second toks))))
                   (multiple-value-bind (host port) (%split-dest dest)
                     (push (%make-rule :action (%action head path lineno)
                                       :principal who :host host :port port
                                       :source (format nil "~a:~d" path lineno))
                           rules)
                     (incf n))))
                (t (error "cl-transport: ~a:~d: unknown directive ~s" path lineno (first toks)))))))))
    (sb-thread:with-mutex (*rules-lock*)
      (setf *rules* (if replace (nreverse rules) (append *rules* (nreverse rules)))
            *requirements* (if replace (nreverse reqs) (append *requirements* (nreverse reqs))))
      (incf *policy-generation*))
    (when default (setf *default-action* default))
    n))

(defun %action (word path lineno)
  (let ((w (string-downcase word)))
    (cond ((string= w "allow") :allow)
          ((string= w "deny") :deny)
          (t (error "cl-transport: ~a:~d: expected allow or deny, got ~s" path lineno word)))))
