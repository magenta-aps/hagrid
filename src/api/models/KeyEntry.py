"""Django Model."""
from __future__ import unicode_literals
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth.models import Group

#from django.core.exceptions import ValidationError
#from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _lazy
from django.db import models
# from django.utils import timezone
#from simple_history.models import HistoricalRecords

from api.models import util


@python_2_unicode_compatible
class KeyEntry(models.Model):
    """
    """

    class Meta:
        verbose_name = _lazy("key entry")
        verbose_name_plural = _lazy("key entries")

    owner = models.ForeignKey(
        Group,
        related_name="key_entries",
        on_delete=models.PROTECT
    )
    """Group of users who has access to this key entry / service.

    Each of these users will have a password entry kept up to date for each of
    their public keys (by invariant).
    """

    title = models.CharField(max_length=util.MAX_LENGTH_NUMBER, blank=True)
    """Free-text decription or title of this key entry / service."""

    username = models.CharField(max_length=util.MAX_LENGTH_NUMBER, blank=True)
    """Plain text username for login at this key entry / service."""

    url = models.CharField(max_length=util.MAX_LENGTH_NUMBER, blank=True)
    """Plain text url for login to this key entry / service."""

    notes = models.CharField(max_length=util.MAX_LENGTH_NUMBER, blank=True)
    """Free-text notes about this key entry / service."""

    def __str__(self):
        return (self.title + " for " + self.username + " @ " + self.url)
