from django.db import models

class SnortAlert(models.Model):
    timestamp = models.DateTimeField()
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10)
    signature = models.TextField()
    classification_id = models.IntegerField(default=0)
    priority = models.IntegerField(default=1)
    message = models.TextField()
    sid = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.timestamp} - {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
