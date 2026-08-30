;;;; names.lisp — an address remembers the name it was resolved from.
;;;;
;;;; CONNECT(2) TAKES AN ADDRESS, NOT A NAME, so by the time a connection reaches the
;;;; gate the interesting half of it is already gone: 209.216.230.207 is not a thing
;;;; anybody wants to write a rule about.  The name existed a moment earlier, in the
;;;; resolver call, and nowhere afterwards.
;;;;
;;;; So the resolver is watched too, and what it returns is remembered.  A rule can then
;;;; say `news.ycombinator.com' and be matched against a connection that only ever
;;;; mentioned an address.
;;;;
;;;; This is a CACHE OF OBSERVATIONS AND NOT A SOURCE OF TRUTH.  An address learned this
;;;; way is one that some caller asked for by that name; it is not proof that the address
;;;; belongs to it, and a host behind a CDN will collect several names honestly.  Rules
;;;; that must be exact should name addresses, which are what the kernel is actually
;;;; given -- see the README.

(in-package #:cl-transport.gate)

(defvar *names* (make-hash-table :test #'equal)
  "address-string -> list of hostnames it has been resolved from, most recent first.")
(defvar *names-lock* (sb-thread:make-mutex :name "gate-names"))
(defvar *name-limit* 4096
  "Stop learning new addresses past this many.  A cache nobody empties is a leak, and
   the failure mode of a full one (rules stop matching by name) is visible, where the
   failure mode of an unbounded one is a machine that slowly stops.")

(defun address-string (address)
  "A printable form of ADDRESS: dotted quad for IPv4, colon-hex for IPv6, else princ.
   This string is the key everything else in the gate joins on."
  (cond ((and (vectorp address) (= (length address) 4))
         (format nil "~{~d~^.~}" (coerce address 'list)))
        ((and (vectorp address) (= (length address) 16))
         (string-downcase
          (format nil "~{~x~^:~}"
                  (loop for i from 0 below 16 by 2
                        collect (logior (ash (aref address i) 8) (aref address (1+ i)))))))
        (t (princ-to-string address))))

(defun note-name (address name)
  "Record that ADDRESS was resolved from NAME."
  (when (and address name)
    (let ((key (address-string address)))
      (sb-thread:with-mutex (*names-lock*)
        (let ((have (gethash key *names*)))
          (when (or have (< (hash-table-count *names*) *name-limit*))
            (setf (gethash key *names*)
                  (cons name (remove name have :test #'string-equal)))))))))

(defun names-for (address-string)
  "Every hostname ADDRESS-STRING has been seen resolved from, most recent first."
  (sb-thread:with-mutex (*names-lock*) (copy-list (gethash address-string *names*))))

(defun forget-names ()
  (sb-thread:with-mutex (*names-lock*) (clrhash *names*)))
