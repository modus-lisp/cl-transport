;;;; record.lisp — what was asked for, and what was decided.
;;;;
;;;; The log is the whole point of the first cut.  A policy written before anybody has
;;;; watched the machine is a guess, and the interesting question -- what DOES this
;;;; desktop talk to, when nobody asked it to? -- is answered by a record and not by a
;;;; rule.  So the record is kept whatever the verdict, and a denial is an entry like
;;;; any other, with the rule that caused it named.

(in-package #:cl-transport.gate)

(defstruct (connection (:constructor %make-connection))
  (at 0 :type integer)                  ; universal time
  (principal "" :type string)
  (host "" :type string)                ; the address, as a string
  (names '() :type list)                ; hostnames it has been resolved from
  (port 0)
  (action :allow :type keyword)
  (rule nil))

(defvar *connections* '() "Most recent first.")
(defvar *record-lock* (sb-thread:make-mutex :name "gate-record"))
(defvar *record-limit* 2000
  "Keep at most this many entries.  A desktop left running for a week should not be
   holding every connection it ever made.")

(defun note-connection (principal host names port action rule)
  (sb-thread:with-mutex (*record-lock*)
    (push (%make-connection :at (get-universal-time) :principal principal :host host
                            :names names :port port :action action :rule rule)
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
  "Print the record: who went where, and what was decided."
  (let ((cs (connections :principal principal :action action :limit limit)))
    (if (null cs)
        (format stream "~&cl-transport: nothing recorded~@[ for ~a~]~%" principal)
        (progn
          (format stream "~&~a connection~:p, most recent first~%" (length cs))
          (dolist (c cs)
            (multiple-value-bind (s m h) (decode-universal-time (connection-at c))
              (format stream "  ~2,'0d:~2,'0d:~2,'0d  ~6a  ~24a  ~a:~a~@[  (~a)~]~%"
                      h m s
                      (if (eq (connection-action c) :deny) "DENY" "allow")
                      (connection-principal c)
                      (or (first (connection-names c)) (connection-host c))
                      (connection-port c)
                      (and (connection-rule c) (decision-source (connection-rule c))))))))
    (length cs)))
