;; VulnGuard - Vulnerability Detection and Monitoring System
;; A decentralized vulnerability detection platform for Clarity smart contracts

;; Constants
(define-constant SYSTEM_MANAGER tx-sender)
(define-constant ERR_ACCESS_FORBIDDEN (err u400))
(define-constant ERR_RECORD_MISSING (err u401))
(define-constant ERR_DETECTOR_EXISTS (err u402))
(define-constant ERR_DETECTOR_INVALID (err u403))
(define-constant ERR_PAYMENT_REQUIRED (err u404))

;; Data Variables
(define-data-var detection-counter uint u0)
(define-data-var monitoring-fee uint u1500000) ;; 1.5 STX in microSTX
(define-data-var system-active bool true)

;; Data Maps
(define-map vulnerability-reports
    { report-id: uint }
    {
        target-contract: principal,
        detector-agent: principal,
        detection-timestamp: uint,
        threat-level: uint,
        issues-identified: uint,
        report-digest: (string-ascii 64),
        validation-confirmed: bool,
        priority-rating: uint
    }
)

(define-map security-detectors
    { detector-principal: principal }
    {
        trust-points: uint,
        total-detections: uint,
        confirmed-detections: uint,
        detector-operational: bool,
        detection-accuracy: uint
    }
)

(define-map contract-monitoring
    { target-contract: principal }
    {
        current-report-id: uint,
        monitoring-sessions: uint,
        optimal-threat-level: uint,
        last-detection-block: uint
    }
)

;; Authorization map for verified detectors
(define-map verified-detectors principal bool)

;; Detection earnings tracking
(define-map detector-payments principal uint)

;; Public Functions

;; Register a new vulnerability detector
(define-public (register-detector)
    (let ((caller tx-sender))
        (asserts! (var-get system-active) ERR_ACCESS_FORBIDDEN)
        (asserts! (is-none (map-get? security-detectors { detector-principal: caller })) ERR_DETECTOR_EXISTS)
        (map-set security-detectors 
            { detector-principal: caller }
            {
                trust-points: u0,
                total-detections: u0,
                confirmed-detections: u0,
                detector-operational: true,
                detection-accuracy: u50
            }
        )
        (ok true)
    )
)

;; Submit a vulnerability detection report
(define-public (submit-detection (target-contract principal) (threat-level uint) (issues-identified uint) (report-digest (string-ascii 64)) (priority-rating uint))
    (let (
        (caller tx-sender)
        (new-report-id (+ (var-get detection-counter) u1))
        (detector-info (unwrap! (map-get? security-detectors { detector-principal: caller }) ERR_DETECTOR_INVALID))
    )
        ;; Ensure system is active and detector is operational
        (asserts! (var-get system-active) ERR_ACCESS_FORBIDDEN)
        (asserts! (get detector-operational detector-info) ERR_DETECTOR_INVALID)
        
        ;; Process monitoring fee
        (try! (stx-transfer? (var-get monitoring-fee) caller SYSTEM_MANAGER))
        
        ;; Create vulnerability report
        (map-set vulnerability-reports
            { report-id: new-report-id }
            {
                target-contract: target-contract,
                detector-agent: caller,
                detection-timestamp: stacks-block-height,
                threat-level: threat-level,
                issues-identified: issues-identified,
                report-digest: report-digest,
                validation-confirmed: false,
                priority-rating: priority-rating
            }
        )
        
        ;; Update detector statistics
        (map-set security-detectors
            { detector-principal: caller }
            (merge detector-info { total-detections: (+ (get total-detections detector-info) u1) })
        )
        
        ;; Update contract monitoring data
        (let ((monitoring-data (default-to 
                { current-report-id: u0, monitoring-sessions: u0, optimal-threat-level: u100, last-detection-block: u0 }
                (map-get? contract-monitoring { target-contract: target-contract })
            )))
            (map-set contract-monitoring
                { target-contract: target-contract }
                {
                    current-report-id: new-report-id,
                    monitoring-sessions: (+ (get monitoring-sessions monitoring-data) u1),
                    optimal-threat-level: (if (< threat-level (get optimal-threat-level monitoring-data)) 
                                         threat-level 
                                         (get optimal-threat-level monitoring-data)),
                    last-detection-block: stacks-block-height
                }
            )
        )
        
        ;; Track detector payments
        (let ((current-payments (default-to u0 (map-get? detector-payments caller))))
            (map-set detector-payments caller (+ current-payments (var-get monitoring-fee)))
        )
        
        ;; Update detection counter
        (var-set detection-counter new-report-id)
        
        (ok new-report-id)
    )
)

;; Validate a detection report (only verified detectors can validate others' reports)
(define-public (validate-detection (report-id uint))
    (let (
        (caller tx-sender)
        (report-info (unwrap! (map-get? vulnerability-reports { report-id: report-id }) ERR_RECORD_MISSING))
        (original-detector (get detector-agent report-info))
    )
        ;; Ensure caller is verified and not validating their own report
        (asserts! (default-to false (map-get? verified-detectors caller)) ERR_ACCESS_FORBIDDEN)
        (asserts! (not (is-eq caller original-detector)) ERR_ACCESS_FORBIDDEN)
        
        ;; Mark report as validated
        (map-set vulnerability-reports
            { report-id: report-id }
            (merge report-info { validation-confirmed: true })
        )
        
        ;; Update original detector's reputation
        (let ((detector-info (unwrap! (map-get? security-detectors { detector-principal: original-detector }) ERR_RECORD_MISSING)))
            (map-set security-detectors
                { detector-principal: original-detector }
                (merge detector-info { 
                    confirmed-detections: (+ (get confirmed-detections detector-info) u1),
                    trust-points: (+ (get trust-points detector-info) u25),
                    detection-accuracy: (+ (get detection-accuracy detector-info) u5)
                })
            )
        )
        
        (ok true)
    )
)

;; Admin function to verify detectors
(define-public (verify-detector (detector principal))
    (begin
        (asserts! (is-eq tx-sender SYSTEM_MANAGER) ERR_ACCESS_FORBIDDEN)
        (map-set verified-detectors detector true)
        (ok true)
    )
)

;; Admin function to update monitoring fee
(define-public (update-monitoring-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender SYSTEM_MANAGER) ERR_ACCESS_FORBIDDEN)
        (var-set monitoring-fee new-fee)
        (ok true)
    )
)

;; Admin function to toggle system status
(define-public (toggle-system-status)
    (begin
        (asserts! (is-eq tx-sender SYSTEM_MANAGER) ERR_ACCESS_FORBIDDEN)
        (var-set system-active (not (var-get system-active)))
        (ok (var-get system-active))
    )
)

;; Deactivate detector account
(define-public (deactivate-detector)
    (let (
        (caller tx-sender)
        (detector-info (unwrap! (map-get? security-detectors { detector-principal: caller }) ERR_DETECTOR_INVALID))
    )
        (map-set security-detectors
            { detector-principal: caller }
            (merge detector-info { detector-operational: false })
        )
        (ok true)
    )
)

;; Reactivate detector account
(define-public (reactivate-detector)
    (let (
        (caller tx-sender)
        (detector-info (unwrap! (map-get? security-detectors { detector-principal: caller }) ERR_DETECTOR_INVALID))
    )
        (asserts! (var-get system-active) ERR_ACCESS_FORBIDDEN)
        (map-set security-detectors
            { detector-principal: caller }
            (merge detector-info { detector-operational: true })
        )
        (ok true)
    )
)

;; Boost detector accuracy rating (self-improvement)
(define-public (boost-accuracy (accuracy-boost uint))
    (let (
        (caller tx-sender)
        (detector-info (unwrap! (map-get? security-detectors { detector-principal: caller }) ERR_DETECTOR_INVALID))
    )
        (asserts! (<= accuracy-boost u20) ERR_ACCESS_FORBIDDEN) ;; Max boost of 20 points
        (asserts! (<= (+ (get detection-accuracy detector-info) accuracy-boost) u100) ERR_ACCESS_FORBIDDEN) ;; Max accuracy is 100
        (map-set security-detectors
            { detector-principal: caller }
            (merge detector-info { detection-accuracy: (+ (get detection-accuracy detector-info) accuracy-boost) })
        )
        (ok true)
    )
)

;; Read-only Functions

;; Get vulnerability report details
(define-read-only (get-vulnerability-report (report-id uint))
    (map-get? vulnerability-reports { report-id: report-id })
)

;; Get detector profile
(define-read-only (get-detector-profile (detector-principal principal))
    (map-get? security-detectors { detector-principal: detector-principal })
)

;; Get contract monitoring summary
(define-read-only (get-monitoring-summary (target-contract principal))
    (map-get? contract-monitoring { target-contract: target-contract })
)

;; Get latest detection for a contract
(define-read-only (get-latest-detection (target-contract principal))
    (let ((monitoring-data (map-get? contract-monitoring { target-contract: target-contract })))
        (match monitoring-data
            summary (map-get? vulnerability-reports { report-id: (get current-report-id summary) })
            none
        )
    )
)

;; Get current detection counter
(define-read-only (get-detection-counter)
    (var-get detection-counter)
)

;; Get monitoring fee
(define-read-only (get-monitoring-fee)
    (var-get monitoring-fee)
)

;; Check if detector is verified
(define-read-only (is-verified-detector (detector principal))
    (default-to false (map-get? verified-detectors detector))
)

;; Get detector payments
(define-read-only (get-detector-payments (detector principal))
    (default-to u0 (map-get? detector-payments detector))
)

;; Check system status
(define-read-only (is-system-active)
    (var-get system-active)
)

;; Get system manager
(define-read-only (get-system-manager)
    SYSTEM_MANAGER
)

;; Calculate detector effectiveness rating
(define-read-only (calculate-effectiveness (detector principal))
    (let ((detector-info (map-get? security-detectors { detector-principal: detector })))
        (match detector-info
            data (let ((total (get total-detections data))
                      (confirmed (get confirmed-detections data)))
                (if (> total u0)
                    (some (/ (* confirmed u100) total))
                    (some u0)
                ))
            none
        )
    )
)