;;;; record.lisp — what was asked for, and what was decided.
;;;;
;;;; The log is the whole point of the first cut.  A policy written before anybody has
;;;; watched the machine is a guess, and the interesting question -- what DOES this
;;;; desktop talk to, when nobody asked it to? -- is answered by a record and not by a
;;;; rule.  So the record is kept whatever the verdict, and a denial is an entry like
;;;; any other, with the rule that caused it named.

(in-package #:cl-transport.gate)

(defclass connection ()
  ((at        :initarg :at        :initform 0     :reader connection-at)   ; universal time
   (principal :initarg :principal :initform ""    :reader connection-principal)
   (host      :initarg :host      :initform ""    :reader connection-host) ; address as a string
   (names     :initarg :names     :initform '()   :reader connection-names)
   (port      :initarg :port      :initform 0     :reader connection-port)
   (carrier   :initarg :carrier   :initform :raw  :reader connection-carrier)
   (action    :initarg :action    :initform :allow :reader connection-action)
   (rule      :initarg :rule      :initform nil   :reader connection-rule))
  (:documentation "One outbound connection, and what was decided about it.
    A class and not a struct -- see the note in gate-policy.lisp."))

(defun %make-connection (&key at principal host names port carrier action rule)
  (make-instance 'connection :at at :principal principal :host host :names names
                             :port port :carrier carrier :action action :rule rule))

(defvar *connections* '() "Most recent first.")
(defvar *record-lock* (sb-thread:make-mutex :name "gate-record"))
(defvar *record-limit* 2000
  "Keep at most this many entries.  A desktop left running for a week should not be
   holding every connection it ever made.")

(defun note-connection (principal host names port action rule &optional (carrier *carrier*))
  (sb-thread:with-mutex (*record-lock*)
    (push (%make-connection :at (get-universal-time) :principal principal :host host
                            :names names :port port :action action :rule rule
                            :carrier carrier)
          *connections*)
    (when (> (length *connections*) *record-limit*)
      (setf *connections* (subseq *connections* 0 *record-limit*)))))

(defun connections (&key principal action (limit 100))
  "The record, most recent first, optionally filtered."
  (let ((all (sb-thread:with-mutex (*record-lock*) (copy-list *connections*))))
    (when principal
      (setf all (remove-if-not (lambda (c) (glob-match-p principal (connection-principal c))) all)))
    (when action
      (setf all (remove action all :key #'connection-action :test-not #'eq)))
    (if (and limit (> (length all) limit)) (subseq all 0 limit) all)))

(defun clear-connections ()
  (sb-thread:with-mutex (*record-lock*) (setf *connections* '())) t)

(defun report (&key (stream *standard-output*) (limit 40) principal action)
  "Print the record: who went where, HOW, and what was decided.

   The carrier column is not decoration.  Before a policy can usefully say `require *
   via cl-transport\', somebody has to know what the answer is today -- and the honest
   answer, for a machine where nothing has been moved onto DIAL yet, is that every
   line says `raw\'.  A log that showed only the destination would leave that
   invisible until the requirement was turned on and everything broke at once."
  (let ((cs (connections :principal principal :action action :limit limit)))
    (if (null cs)
        (format stream "~&cl-transport: nothing recorded~@[ for ~a~]~%" principal)
        (progn
          (format stream "~&~a connection~:p, most recent first~%" (length cs))
          (dolist (c cs)
            (multiple-value-bind (s m h) (decode-universal-time (connection-at c))
              (format stream "  ~2,'0d:~2,'0d:~2,'0d  ~5a  ~22a  ~28a  via ~(~a~)~@[  (~a)~]~%"
                      h m s
                      (string-downcase (symbol-name (connection-action c)))
                      (connection-principal c)
                      (format nil "~a:~a"
                              (or (first (connection-names c)) (connection-host c))
                              (connection-port c))
                      (connection-carrier c)
                      (and (connection-rule c) (decision-source (connection-rule c))))))))
    (length cs)))
