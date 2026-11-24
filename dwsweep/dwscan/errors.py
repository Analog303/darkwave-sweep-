class DwError(Exception):
    """Basisfehler."""


class TransportError(DwError):
    """Netzwerkfehler, wiederholbar."""


class BudgetExceeded(DwError):
    """Ressourcenlimit erreicht, Abbruch."""


class NotAuthorized(DwError):
    """Ziel ausserhalb des Scopes."""


class AbortConditions:
    def __init__(self, max_streak: int = 25, max_seconds: int = 0):
        self.max_streak = max_streak
        self.max_seconds = max_seconds
        self.streak = 0
        self.started = 0.0

    def start(self):
        import time
        self.started = time.monotonic()

    def note(self, reachable: bool):
        import time
        self.streak = 0 if reachable else self.streak + 1
        if self.max_streak and self.streak >= self.max_streak:
            raise BudgetExceeded(f"{self.streak} Ziele in Folge unerreichbar")
        if self.max_seconds and time.monotonic() - self.started > self.max_seconds:
            raise BudgetExceeded(f"Zeitbudget {self.max_seconds}s erschoepft")
