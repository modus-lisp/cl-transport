;;;; hook.lisp — the gate itself.
;;;;
;;;; ONE FUNCTION COVERS THE WHOLE IMAGE.  Everything that opens a TCP connection here
;;;; arrives at SB-BSD-SOCKETS:SOCKET-CONNECT: seal calls it directly (and so every
;;;; HTTPS fetch, every relay, cairn's clone), weft's plain-HTTP path calls it, conch
;;;; calls it, and usocket calls it -- which brings cl-tor and cl-transport along
;;;; without either of them knowing.  So does any library out of quicklisp that we have
;;;; never read, which is the case a gate exists for.
;;;;
;;;; That is why this is a HOOK on those operators rather than a function the callers opt into.
;;;; Asking a dozen call sites to route through the gate would police exactly the code
;;;; that agreed to be policed, which is the code least likely to surprise anybody.

(in-package #:cl-transport.gate)

(define-condition blocked (error)
  ((principal :initarg :principal :reader blocked-principal)
   (host      :initarg :host      :reader blocked-host)
   (port      :initarg :port      :reader blocked-port)
   (rule      :initarg :rule      :reader blocked-rule :initform nil))
  (:report (lambda (c s)
             (format s "cl-transport: ~a is not allowed to connect to ~a:~a~@[ (~a)~]"
                     (blocked-principal c) (blocked-host c) (blocked-port c)
                     (let ((r (blocked-rule c))) (and r (decision-source r))))))
  (:documentation
   "Signalled in place of a connection.  A plain ERROR, on purpose: every caller in
    this workspace already wraps connect in a HANDLER-CASE for ERROR because the
    network fails on its own, so a refusal travels the path a failure already had.
    loom prints `load ... failed' and shows a broken page; seal closes its transport;
    nothing needs to learn a new condition to degrade correctly."))

(defvar *principal* nil
  "Who this connection is for, if anybody has said.  NIL means fall back to the
   thread, which is usually enough: this image names its threads after the work
   (`loom-glass-nav', `wm-browse-pump', `glass-music-ticker'), so the default answer
   is already finer than the process name Little Snitch would have to use.")

(defun principal ()
  "The name to hold responsible for a connection made right now."
  (or *principal*
      (let ((n (sb-thread:thread-name sb-thread:*current-thread*)))
        (if (stringp n) n (princ-to-string n)))))

(defmacro with-principal ((name) &body body)
  "Run BODY with connections attributed to NAME.  Nests: an app can name itself and
   a subsystem inside it can be more specific."
  `(let ((*principal* ,name)) ,@body))

(defmacro with-carrier ((carrier) &body body)
  "Run BODY with the bytes declared to be travelling over CARRIER."
  `(let ((*carrier* ,carrier)) ,@body))

;;; ---- the decision cache -----------------------------------------------------
;;;
;;; A DATAGRAM IS NOT A CONNECTION, and gating one means deciding per packet rather
;;; than per socket.  ICE alone sends a steady stream of them during a call, and
;;; walking the rule list for each would put the policy in the media path.  The
;;; verdict for (principal, carrier, host, port) cannot change unless the policy does,
;;; so it is memoised against *POLICY-GENERATION* and thrown away wholesale when that
;;; moves.

(defvar *decisions* (make-hash-table :test #'equal))
(defvar *decisions-generation* -1)
(defvar *decisions-lock* (sb-thread:make-mutex :name "gate-decisions"))

(defun cached-decide (principal host port carrier)
  ;; The cache is the owner's.  On modus a worker decides each datagram itself: a
  ;; verdict written into the shared table would be a store of its own objects.
  (unless (%gate-owner-p)
    (return-from cached-decide (decide principal host port nil carrier)))
  (let ((key (list principal carrier host port)))
    (sb-thread:with-mutex (*decisions-lock*)
      (unless (eql *decisions-generation* *policy-generation*)
        (clrhash *decisions*)
        (setf *decisions-generation* *policy-generation*))
      (multiple-value-bind (hit found) (gethash key *decisions*)
        (if found
            (values (first hit) (second hit))
            (multiple-value-bind (action why) (decide principal host port nil carrier)
              (setf (gethash key *decisions*) (list action why))
              (values action why)))))))

;;; ---- the checks the hooks run ------------------------------------------------

(defun %port-of (args)
  (let ((p (second args))) (if (integerp p) p (or p 0))))

(defun %check (address port)
  "Decide, record, and either return or signal.  For connections, which are rare
   enough to be recorded individually."
  (let* ((host (address-string address))
         (names (names-for host))
         (who (principal)))
    (multiple-value-bind (action why) (decide who host port names *carrier*)
      (note-connection who host names port action why *carrier*)
      (when (eq action :deny)
        (error 'blocked :principal who :host (or (first names) host) :port port :rule why))
      t)))

(defun %check-datagram (address port)
  "The same decision for a packet: cached, and recorded only when the verdict is new.
   A denied datagram is dropped by signalling, exactly as a connection is refused;
   callers that send UDP already tolerate a send failing, because UDP does."
  (let* ((host (address-string address))
         (who (principal)))
    (multiple-value-bind (action why) (cached-decide who host port *carrier*)
      (when (eq action :deny)
        ;; Recorded once per distinct (principal, host, port) rather than per packet:
        ;; a refused media stream would otherwise fill the log with one line per frame
        ;; and push everything else out of it.
        (let ((key (list :logged who host port)))
          (if (%gate-owner-p)
              (unless (gethash key *decisions*)
                (setf (gethash key *decisions*) t)
                (note-connection who host (names-for host) port action why *carrier*))
              (unless (member key *local-logged* :test #'equal)
                (push key *local-logged*)
                (note-connection who host (names-for host) port action why *carrier*))))
        (error 'blocked :principal who :host host :port port :rule why))
      t)))

;;; ---- hooks, in standard Common Lisp ---------------------------------------------
;;;
;;; The gate runs around three operators it does not own.  It used SB-INT:ENCAPSULATE,
;;; which is SBCL's internal package: no other Lisp has it, so on modus the whole system
;;; failed at READ time.  Two standard mechanisms do the same job, chosen per operator
;;; when the gate is armed, because whether an operator is a generic function is a
;;; property of the implementation and not of the API:
;;;
;;;   a GENERIC FUNCTION gets an :AROUND method (EVAL of a DEFMETHOD, so no MOP), and
;;;     disarming removes exactly that method with REMOVE-METHOD.  Replacing a generic
;;;     function's definition instead would break the next DEFMETHOD on it.  On SBCL this
;;;     is SOCKET-CONNECT and SOCKET-SEND.
;;;   a PLAIN FUNCTION is replaced through (SETF FDEFINITION), its original kept and put
;;;     back on disarm -- only if the definition is still ours, so a later redefinition
;;;     is never undone.  On SBCL this is GET-HOST-BY-NAME; on modus, all three.
;;;
;;; Either way the wrapper is called as (wrapper next arg...), NEXT calling the operator
;;; with the same arguments.

(defvar *hooks* '()
  "One entry per installed hook: (name :method method) or (name :function original wrapper).")

(defun %hooked-p (name) (and (assoc name *hooks*) t))

(defun %hook (name required specializer wrapper)
  "Run WRAPPER around the operator NAME.  REQUIRED is how many required parameters the
   operator takes and SPECIALIZER the class its first is specialized on, for the case
   where it is a generic function.  Idempotent."
  (unless (%hooked-p name)
    (let ((f (fdefinition name)))
      (if (typep f 'generic-function)
          (let* ((rest (loop for i from 1 below required
                             collect (intern (format nil "ARG~d" i) '#:cl-transport.gate)))
                 (method (eval `(defmethod ,name :around ((arg0 ,specializer) ,@rest &rest more)
                                  (apply ',wrapper
                                         (lambda (&rest args) (apply #'call-next-method args))
                                         arg0 ,@rest more)))))
            (push (list name :method method) *hooks*))
          (let ((ours (lambda (&rest args) (apply wrapper f args))))
            (setf (fdefinition name) ours)
            (push (list name :function f ours) *hooks*)))))
  t)

(defun %unhook (name)
  (let ((entry (assoc name *hooks*)))
    (when entry
      (destructuring-bind (kind thing &optional ours) (rest entry)
        (ecase kind
          (:method (remove-method (fdefinition name) thing))
          (:function (when (eq (fdefinition name) ours)
                       (setf (fdefinition name) thing)))))
      (setf *hooks* (remove entry *hooks*))))
  t)

(defun arm ()
  "Install the gate.  Idempotent.  The thread that arms it owns its bookkeeping (on
   modus that must be the main thread -- see gate-channel.lisp)."
  (%gate-adopt-owner)
  (%hook 'sb-bsd-sockets:socket-connect 1 'sb-bsd-sockets:socket
         (lambda (fn socket &rest args)
           ;; A LOCAL SOCKET IS NOT A DEPARTURE.  Unix-domain connects take a path rather
           ;; than an address and never leave the machine; glass's control socket, its
           ;; seats and the local viewer are all on one, and recording them would bury
           ;; the connections that matter under thousands that cannot go anywhere.
           (if (stringp (first args))
               (apply fn socket args)
               (progn (%check (first args) (%port-of args))
                      (apply fn socket args)))))
  ;; UDP.  A datagram socket usually never connects: the destination rides on each
  ;; SOCKET-SEND, which is how ICE and TURN reach the world, and a gate that only
  ;; watched CONNECT could not see any of it -- the largest hole in the first cut of
  ;; this, and the one that mattered most, since that is the path to a phone.
  (%hook 'sb-bsd-sockets:socket-send 3 'sb-bsd-sockets:socket
         (lambda (fn socket buffer length &rest args)
           (let ((dest (getf args :address)))
             ;; No :ADDRESS means the socket is connected and was gated when it connected.
             (when (and dest (listp dest) (not (stringp (first dest))))
               (%check-datagram (first dest) (or (second dest) 0)))
             (apply fn socket buffer length args))))
  ;; Watched only so an address can be named -- see names.lisp.  Resolution is not
  ;; itself gated: a policy that let a name be looked up and then refused the
  ;; connection is easier to read in the log than one that fails at the resolver.
  (%hook 'sb-bsd-sockets:get-host-by-name 1 't
         (lambda (fn name &rest args)
           (let ((ent (apply fn name args)))
             (when ent
               (ignore-errors
                (dolist (a (sb-bsd-sockets:host-ent-addresses ent)) (note-name a name))))
             ent)))
  t)

(defun disarm ()
  "Remove the gate.  The record and the rules survive it."
  (%gate-drain)
  (%unhook 'sb-bsd-sockets:socket-connect)
  (%unhook 'sb-bsd-sockets:socket-send)
  (%unhook 'sb-bsd-sockets:get-host-by-name)
  t)

(defun armed-p ()
  (%hooked-p 'sb-bsd-sockets:socket-connect))


;;; ---- boot -------------------------------------------------------------------
;;;
;;; A GATE THAT IS ARMED LATE IS NOT A GATE.  Everything interesting about this
;;; depends on nothing having connected yet, so the intended use is to initialize
;;; while the image is still starting -- before a seat is served, before the browser
;;; exists, before the first relay is dialled.
;;;
;;; Loading this system does NOT arm anything by itself: a library that started
;;; policing its host the moment it was compiled in would be a rude thing to depend
;;; on, and cl-consensus and cl-tor both pull cl-transport in for DIAL alone.  The
;;; arming is one call, and it is a no-op when there is no policy to apply.

(defparameter *policy-path-variable* "TRANSPORT_POLICY"
  "Environment variable naming the policy document.")

(defparameter *default-policy-paths*
  (list (merge-pathnames ".config/transport-policy.conf" (user-homedir-pathname))
        #p"/etc/transport-policy.conf")
  "Where a policy is looked for when the environment says nothing.")

(defun policy-path ()
  "The policy document to use, or NIL if there is none."
  (let ((env (sb-ext:posix-getenv *policy-path-variable*)))
    (if (and env (plusp (length env)))
        ;; NAMED EXPLICITLY AND ABSENT IS AN ERROR, not a silent open gate: somebody
        ;; who set the variable meant for a policy to be in force, and starting
        ;; without one because of a typo is the failure they would least like.
        (or (probe-file env)
            (error "cl-transport: ~a names ~s, which does not exist"
                   *policy-path-variable* env))
        (find-if #'probe-file *default-policy-paths*))))

(defun initialize (&key path (arm t))
  "Load a policy and arm the gate.  Returns the path in force, or NIL if there was
   no policy to load (in which case nothing is armed and nothing is policed).

   Call this at boot, before anything opens a connection."
  (let ((p (or path (policy-path))))
    (when p
      (load-policy p)
      (when arm (arm))
      (truename p))))
