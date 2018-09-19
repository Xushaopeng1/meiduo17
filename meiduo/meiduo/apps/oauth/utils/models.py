from django.db import models


class BaseModel(models.Model):

    createtime = models.DateField(auto_now_add=True,verbose_name='创建时间')
    updatetime = models.DateField(auto_now=True,verbose_name='更新时间')

    class Meta:
        #定义该模型为抽象，迁移时不会创建该模型表 ，用于继承使用
        abstract=True