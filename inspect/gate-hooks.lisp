;;;; gate-hooks.lisp — the gate's hooks leave the operators as they found them.
;;;;
;;;;   sbcl --script inspect/gate-hooks.lisp
;;;;
;;;; transport-gate.lisp checks what the gate DECIDES.  This checks how it attaches: an
;;;; :around method on an operator that is a generic function, a replaced definition on
;;;; one that is not, and in both cases nothing left behind after DISARM -- and nothing
;;;; of anybody else's undone by it.

(require :asdf)
(require :sb-bsd-sockets)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport")))

(defpackage #:gate-hooks-test (:use #:cl)) (in-package #:gate-hooks-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got expect)
  (if (equal got expect)
      (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a~%       got    ~s~%       expect ~s~%" name got expect))))

(defun method-count (name)
  (let ((f (fdefinition name)))
    (if (typep f 'generic-function)
        (length (funcall (intern "GENERIC-FUNCTION-METHODS"
                                 (or (find-package "SB-MOP") (find-package "CLOSER-MOP")))
                         f))
        :not-generic)))

(format t "~&== the gate's hooks~%")
(let ((connect-before (fdefinition 'sb-bsd-sockets:socket-connect))
      (connect-methods (method-count 'sb-bsd-sockets:socket-connect))
      (send-methods (method-count 'sb-bsd-sockets:socket-send))
      (resolve-before (fdefinition 'sb-bsd-sockets:get-host-by-name)))
  (cl-transport.gate:arm)
  (cl-transport.gate:arm)
  (ok "armed" (cl-transport.gate:armed-p) t)
  (when (typep connect-before 'generic-function)
    (ok "socket-connect stays the same generic function, with one :around added (arming twice)"
        (list (eq (fdefinition 'sb-bsd-sockets:socket-connect) connect-before)
              (method-count 'sb-bsd-sockets:socket-connect))
        (list t (1+ connect-methods)))
    (ok "socket-send has one :around added" (method-count 'sb-bsd-sockets:socket-send)
        (1+ send-methods))
    ;; Somebody else defines a method while the gate is armed: still possible, because
    ;; the operator is still a generic function.  (Replacing it would have broken this.)
    (let ((m (eval '(defmethod sb-bsd-sockets:socket-connect :before
                     ((s sb-bsd-sockets:socket) &rest args) (declare (ignore args)) nil))))
      (ok "another program can still define a method while the gate is armed"
          (and (typep m 'method) t) t)
      (remove-method (fdefinition 'sb-bsd-sockets:socket-connect) m)))
  (ok "get-host-by-name is wrapped while armed"
      (eq (fdefinition 'sb-bsd-sockets:get-host-by-name) resolve-before) nil)
  ;; The wrapper still answers: names resolve through it.
  (ok "a name still resolves through the hook"
      (and (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name "localhost")) t) t)

  (cl-transport.gate:disarm)
  (ok "disarmed" (cl-transport.gate:armed-p) nil)
  (ok "socket-connect is exactly what it was"
      (list (eq (fdefinition 'sb-bsd-sockets:socket-connect) connect-before)
            (method-count 'sb-bsd-sockets:socket-connect))
      (list t connect-methods))
  (ok "socket-send has its methods back to what they were"
      (method-count 'sb-bsd-sockets:socket-send) send-methods)
  (ok "get-host-by-name is the original function again"
      (eq (fdefinition 'sb-bsd-sockets:get-host-by-name) resolve-before) t)

  ;; A plain function redefined by somebody else while the gate is armed: disarming must
  ;; not put the old definition back over theirs.
  (cl-transport.gate:arm)
  ;; Checked by what ANSWERS rather than by EQ: on modus a closure made in a toplevel
  ;; form is not EQ to what FDEFINITION hands back once it is installed, though calling
  ;; it is the same.  What matters is whose definition runs.
  (let ((theirs (lambda (name &rest args)
                  (if (equal name "theirs.invalid") :theirs (apply resolve-before name args)))))
    (setf (fdefinition 'sb-bsd-sockets:get-host-by-name) theirs)
    (cl-transport.gate:disarm)
    (ok "disarm does not undo somebody else's redefinition"
        (sb-bsd-sockets:get-host-by-name "theirs.invalid") :theirs)
    (setf (fdefinition 'sb-bsd-sockets:get-host-by-name) resolve-before)))

(format t "~&~d passed, ~d failed~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
