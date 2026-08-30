;;;; gate-packages.lisp — cl-transport's outbound gate.

(defpackage #:cl-transport.gate
  (:use #:cl)
  (:documentation
   "The gate on cl-transport's outbound side: every connection this image opens,
    recorded, and subject to a policy that can name not only where the bytes may go
    but HOW THEY MAY TRAVEL.

    Little Snitch watches a Unix machine from outside its processes, which is why it
    needs a kernel extension and why the most it can say about this one is `sbcl
    wants to connect'.  From inside, both halves improve: the gate is a function
    rather than a driver, and a principal can be finer than a process -- the browser
    window, the podcast fetcher, the relay client, each distinct within the one image
    a kernel could only see whole.

    DIAL is where a carrier is chosen, so it is where the carrier is declared; the
    gate sits under the socket, so a requirement holds even over code that never
    called DIAL.  A connection nobody dialled carries :RAW and satisfies no
    requirement at all, which is what lets a policy say `require * via any' and mean
    MUST USE CL-TRANSPORT.")
  (:export
   ;; arming
   #:arm #:disarm #:armed-p #:initialize #:policy-path
   ;; who is asking, and how they travel
   #:*principal* #:principal #:with-principal
   #:*carrier* #:with-carrier #:carrier-satisfies-p
   ;; policy
   #:load-policy #:policy-rules #:policy-requirements #:clear-policy
   #:add-rule #:require-carrier #:*default-action* #:*allow-loopback*
   #:decide #:decision-source #:carrier-violation
   #:requirement-carrier #:requirement-principal
   ;; the record
   #:connections #:clear-connections #:report #:*record-limit*
   #:connection-principal #:connection-host #:connection-port
   #:connection-action #:connection-rule #:connection-at #:connection-carrier
   #:connection-names #:connection-plist
   ;; refusal
   #:blocked #:blocked-principal #:blocked-host #:blocked-port))
