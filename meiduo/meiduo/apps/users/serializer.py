import re
from django_redis import get_redis_connection

from rest_framework import serializers
from rest_framework_jwt.settings import api_settings

from celery_tasks.email.tasks import send_email
from users.models import User


'''
username	str	是	用户名
password	str	是	密码
password2	str	是	确认密码
sms_code	str	是	短信验证码
mobile	str	是	手机号
allow	str	是	是否同意用户协议

'''


class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(max_length=20, min_length=8, write_only=True)
    sms_code = serializers.CharField(max_length=6, min_length=6, write_only=True)
    allow = serializers.CharField(write_only=True)
    token = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'mobile', 'username', 'password', 'password2', 'sms_code', 'allow', 'token')
        extra_kwargs = {
            'username': {
                'max_length': 20,
                'min_length': 5,
                'error_messages': {
                    'max_length': '名字过长',
                    'min_length': '名字过短'
                }
            },
            'password': {
                'write_only': True,
                'max_length': 20,
                'min_length': 8,
                'error_messages': {
                    'max_length': '密码过长',
                    'min_length': '密码过短'
                }
            },
        }

    # 判断手机格式
    def validate_mobile(self, value):

        if not re.match(r'1[3-9]\d{9}$', value):
            return serializers.ValidationError('手机格式不正确')

        return value

    def validate_allow(self, value):

        if value != 'true':
            return serializers.ValidationError('未选中')

        return value

    def validate(self, attrs):
        # 密码判断
        if attrs['password'] != attrs['password2']:
            return serializers.ValidationError('密码不一致')

        # 判断短信
        # 1 先获取缓存中短信
        print(attrs['mobile'])
        conn = get_redis_connection('verify')

        real_sms_code = conn.get('sms_code_%s' % attrs['mobile'])
        print(real_sms_code)
        if not real_sms_code:
            raise serializers.ValidationError('短信验证码失效')

        if attrs['sms_code'] != real_sms_code.decode():
            raise serializers.ValidationError('短信验证码错误')

        return attrs

    def create(self, validated_data):

        print(validated_data)
        # 删除不需要保存的字段数据
        del validated_data['password2']
        del validated_data['sms_code']
        del validated_data['allow']
        print(validated_data)

        # User.objects.create_user()
        user = super().create(validated_data)

        # 明文密码加密
        user.set_password(validated_data['password'])
        user.save()

        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)

        user.token = token

        return user


class UserDatilSerializer(serializers.ModelSerializer):
    """用户相信信息序列化器"""
    print(111)
    class Meta:
        model = User
        fields=('id', 'username', 'mobile', 'email', 'email_active')


class EmailSerializer(serializers.ModelSerializer):
    """邮箱序列化器"""
    class Meta:
        model = User
        fields = ("id",'email')
        extra_kwargs={
            'email':{
                'required':True
            }
        }

    def update(self, instance, validated_data):
        print(validated_data)
        email = validated_data['email']
        instance.email = email
        instance.save()
        #生成验证链接
        verify_url=instance.generate_verify_email_url()
        #发送验证邮件
        send_email.delay(email,verify_url)
        return instance