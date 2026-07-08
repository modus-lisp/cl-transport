;;;; src/util.lisp — tiny byte helpers so cl-transport is self-contained (no cl-tor dep).

(defpackage #:cl-transport.util
  (:use #:cl)
  (:export #:octets #:cat #:u8 #:u16be #:ascii->bytes))

(in-package #:cl-transport.util)

(defun octets (n) (make-array n :element-type '(unsigned-byte 8)))

(defun cat (&rest vs)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) vs))

(defun u8 (b)
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (logand b #xff)))

(defun u16be (n)
  (make-array 2 :element-type '(unsigned-byte 8)
                :initial-contents (list (logand (ash n -8) #xff) (logand n #xff))))

(defun ascii->bytes (s)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))
