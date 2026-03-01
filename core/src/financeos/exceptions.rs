use super::parser::FinancialStatement;
use serde::{Deserialize, Serialize};
use crate::error::CoreResult;

/// Exception detected in financial statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub exception_id: String,
    pub transaction_id: String,
    pub date: String,
    pub amount: f64,
    pub rule_triggered: String,
    pub severity: String, // HIGH/MEDIUM/LOW
    pub description: String,
    pub recommended_action: String,
}

/// Exception detection engine
pub struct ExceptionDetector {
    threshold: f64,
}

impl ExceptionDetector {
    pub fn new() -> Self {
        ExceptionDetector {
            threshold: 10000.0, // $10,000 default
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        ExceptionDetector { threshold }
    }

    /// Detect all exceptions in statement
    pub fn detect_exceptions(&self, statement: &FinancialStatement) -> CoreResult<Vec<Exception>> {
        let mut exceptions = Vec::new();

        // Rule 1: Threshold violations
        for tx in &statement.transactions {
            if tx.amount > self.threshold {
                exceptions.push(Exception {
                    exception_id: format!("EXC_THRESHOLD_{}", &tx.transaction_id[..16.min(tx.transaction_id.len())]),
                    transaction_id: tx.transaction_id.clone(),
                    date: tx.date.clone(),
                    amount: tx.amount,
                    rule_triggered: "THRESHOLD_VIOLATION".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Transaction amount ${:.2} exceeds threshold ${:.2}", tx.amount, self.threshold),
                    recommended_action: "Manual approval required for large transactions".to_string(),
                });
            }
        }

        // Rule 2: Duplicate detection (same amount + account within 24 hours)
        for i in 0..statement.transactions.len() {
            for j in (i + 1)..statement.transactions.len() {
                let tx1 = &statement.transactions[i];
                let tx2 = &statement.transactions[j];

                if (tx1.amount - tx2.amount).abs() < 0.01
                    && tx1.account == tx2.account
                    && days_between(&tx1.date, &tx2.date) <= 1
                {
                    exceptions.push(Exception {
                        exception_id: format!("EXC_DUPLICATE_{}", &tx1.transaction_id[..16.min(tx1.transaction_id.len())]),
                        transaction_id: tx1.transaction_id.clone(),
                        date: tx1.date.clone(),
                        amount: tx1.amount,
                        rule_triggered: "DUPLICATE_DETECTED".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: format!(
                            "Duplicate transaction detected: ${:.2} in {} on similar date",
                            tx1.amount, tx1.account
                        ),
                        recommended_action: "Verify transaction not a duplicate entry".to_string(),
                    });
                }
            }
        }

        // Rule 3: Round number detection (suspiciously round amounts)
        for tx in &statement.transactions {
            if is_suspiciously_round(tx.amount) {
                exceptions.push(Exception {
                    exception_id: format!("EXC_ROUND_{}", &tx.transaction_id[..16.min(tx.transaction_id.len())]),
                    transaction_id: tx.transaction_id.clone(),
                    date: tx.date.clone(),
                    amount: tx.amount,
                    rule_triggered: "ROUND_NUMBER".to_string(),
                    severity: "LOW".to_string(),
                    description: format!("Transaction amount ${:.2} is suspiciously round", tx.amount),
                    recommended_action: "Review for possible rounding or estimate".to_string(),
                });
            }
        }

        // Rule 4: Category anomaly (unexpected categories for account)
        let category_patterns = get_category_patterns();
        for tx in &statement.transactions {
            if let Some(valid_cats) = category_patterns.get(tx.account.as_str()) {
                if !valid_cats.contains(&tx.category.as_str()) {
                    exceptions.push(Exception {
                        exception_id: format!("EXC_ANOMALY_{}", &tx.transaction_id[..16.min(tx.transaction_id.len())]),
                        transaction_id: tx.transaction_id.clone(),
                        date: tx.date.clone(),
                        amount: tx.amount,
                        rule_triggered: "CATEGORY_ANOMALY".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: format!(
                            "Unexpected category '{}' for account '{}'",
                            tx.category, tx.account
                        ),
                        recommended_action: "Confirm correct categorization".to_string(),
                    });
                }
            }
        }

        // Sort by severity (HIGH first)
        exceptions.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "HIGH" => 0,
                "MEDIUM" => 1,
                _ => 2,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        Ok(exceptions)
    }
}

/// Days between two dates (simplified)
fn days_between(date1: &str, date2: &str) -> u32 {
    let parse_date = |d: &str| -> (u32, u32, u32) {
        let parts: Vec<&str> = d.split('-').collect();
        if parts.len() == 3 {
            (
                parts[0].parse().unwrap_or(2026),
                parts[1].parse().unwrap_or(1),
                parts[2].parse().unwrap_or(1),
            )
        } else {
            (2026, 1, 1)
        }
    };

    let (y1, m1, d1) = parse_date(date1);
    let (y2, m2, d2) = parse_date(date2);

    // Simplified: just look at day difference if same month
    if y1 == y2 && m1 == m2 {
        (d1 as i32 - d2 as i32).unsigned_abs()
    } else if y1 == y2 && (m1 as i32 - m2 as i32).unsigned_abs() == 1 {
        // Different months: assume 30 days
        30 - d1.min(d2)
    } else {
        99 // Far apart
    }
}

/// Check if amount is suspiciously round
fn is_suspiciously_round(amount: f64) -> bool {
    let round_numbers = [100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0];
    for &round in &round_numbers {
        if (amount - round).abs() < 0.01 {
            return true;
        }
    }
    false
}

/// Category patterns by account
fn get_category_patterns() -> std::collections::HashMap<&'static str, Vec<&'static str>> {
    let mut patterns = std::collections::HashMap::new();
    patterns.insert(
        "checking",
        vec!["salary", "utilities", "groceries", "transfer", "withdrawal"],
    );
    patterns.insert(
        "savings",
        vec!["transfer", "interest", "deposit", "withdrawal"],
    );
    patterns.insert(
        "credit_card",
        vec!["purchase", "payment", "fee", "interest", "refund"],
    );
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::financeos::parser::Transaction;

    fn sample_statement() -> FinancialStatement {
        FinancialStatement {
            statement_id: "STMT_TEST".to_string(),
            period_start: "2026-01-01".to_string(),
            period_end: "2026-01-31".to_string(),
            transactions: vec![
                Transaction {
                    transaction_id: "FINANCE_CHK_0001".to_string(),
                    date: "2026-01-05".to_string(),
                    amount: 15000.0, // Threshold violation
                    account: "checking".to_string(),
                    category: "salary".to_string(),
                    description: "Large salary".to_string(),
                },
                Transaction {
                    transaction_id: "FINANCE_CHK_0002".to_string(),
                    date: "2026-01-10".to_string(),
                    amount: 5000.0, // Round number
                    account: "checking".to_string(),
                    category: "transfer".to_string(),
                    description: "Round transfer".to_string(),
                },
                Transaction {
                    transaction_id: "FINANCE_SAV_0001".to_string(),
                    date: "2026-01-15".to_string(),
                    amount: 1000.0,
                    account: "savings".to_string(),
                    category: "purchase".to_string(), // Anomaly
                    description: "Anomalous category".to_string(),
                },
            ],
            summary: super::super::parser::StatementSummary {
                total_amount: 21000.0,
                transaction_count: 3,
                accounts: vec!["checking".to_string(), "savings".to_string()],
                categories: vec!["salary".to_string(), "transfer".to_string(), "purchase".to_string()],
                date_range: ("2026-01-05".to_string(), "2026-01-15".to_string()),
            },
        }
    }

    #[test]
    fn test_threshold_detection() {
        let detector = ExceptionDetector::new();
        let stmt = sample_statement();
        let exceptions = detector.detect_exceptions(&stmt).unwrap();

        let threshold_exceptions: Vec<_> = exceptions
            .iter()
            .filter(|e| e.rule_triggered == "THRESHOLD_VIOLATION")
            .collect();
        assert!(threshold_exceptions.len() > 0);
    }

    #[test]
    fn test_round_number_detection() {
        let detector = ExceptionDetector::new();
        let stmt = sample_statement();
        let exceptions = detector.detect_exceptions(&stmt).unwrap();

        let round_exceptions: Vec<_> = exceptions
            .iter()
            .filter(|e| e.rule_triggered == "ROUND_NUMBER")
            .collect();
        assert!(round_exceptions.len() > 0);
    }

    #[test]
    fn test_category_anomaly_detection() {
        let detector = ExceptionDetector::new();
        let stmt = sample_statement();
        let exceptions = detector.detect_exceptions(&stmt).unwrap();

        let anomaly_exceptions: Vec<_> = exceptions
            .iter()
            .filter(|e| e.rule_triggered == "CATEGORY_ANOMALY")
            .collect();
        assert!(anomaly_exceptions.len() > 0);
    }

    #[test]
    fn test_severity_ordering() {
        let detector = ExceptionDetector::new();
        let stmt = sample_statement();
        let exceptions = detector.detect_exceptions(&stmt).unwrap();

        if exceptions.len() > 1 {
            let high_count = exceptions.iter().filter(|e| e.severity == "HIGH").count();
            let medium_count = exceptions.iter().filter(|e| e.severity == "MEDIUM").count();
            // HIGH should come before MEDIUM in sorted list
            if high_count > 0 && medium_count > 0 {
                let first_high = exceptions.iter().position(|e| e.severity == "HIGH").unwrap();
                let first_medium = exceptions.iter().position(|e| e.severity == "MEDIUM").unwrap();
                assert!(first_high < first_medium);
            }
        }
    }

    #[test]
    fn test_custom_threshold() {
        let detector = ExceptionDetector::with_threshold(20000.0);
        let stmt = sample_statement();
        let exceptions = detector.detect_exceptions(&stmt).unwrap();

        let threshold_exceptions: Vec<_> = exceptions
            .iter()
            .filter(|e| e.rule_triggered == "THRESHOLD_VIOLATION")
            .collect();
        // With higher threshold, 15000 should not trigger
        assert!(threshold_exceptions.is_empty());
    }
}
