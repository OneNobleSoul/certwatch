from certwatch.evaluate import Status, evaluate, exit_code_for, rank


def test_ok_above_warn():
    assert evaluate(60) is Status.OK


def test_warning_boundary():
    assert evaluate(21) is Status.WARNING
    assert evaluate(22) is Status.OK


def test_critical_boundary():
    assert evaluate(7) is Status.CRITICAL
    assert evaluate(8) is Status.WARNING


def test_expired_is_negative():
    assert evaluate(-1) is Status.EXPIRED
    assert evaluate(0) is Status.CRITICAL


def test_none_is_error():
    assert evaluate(None) is Status.ERROR


def test_custom_thresholds():
    assert evaluate(30, warn=45, critical=14) is Status.WARNING
    assert evaluate(10, warn=45, critical=14) is Status.CRITICAL


def test_exit_code_worst_wins():
    assert exit_code_for([Status.OK, Status.WARNING, Status.CRITICAL]) == 2
    assert exit_code_for([Status.OK, Status.WARNING]) == 1
    assert exit_code_for([Status.OK]) == 0
    assert exit_code_for([Status.ERROR]) == 3


def test_exit_code_empty():
    assert exit_code_for([]) == 0


def test_rank_orders_expired_worst():
    assert rank(Status.EXPIRED) > rank(Status.ERROR) > rank(Status.CRITICAL)
    assert rank(Status.CRITICAL) > rank(Status.WARNING) > rank(Status.OK)
