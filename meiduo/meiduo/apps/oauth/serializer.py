from rest_framework import serializers
from itsdangerous import TimedJSONWebSignatureSerializer as TJS
from django.conf import settings
from django_redis import get_redis_connection
from rest_framework_jwt.settings import api_settings

from oauth.models import OAuthQQUser
from users.models import User
'''
mobile	str	是	手机号
password	str	是	密码
sms_code	str	是	短信验证码
access_token	str	是	凭据 （包含openid)

'''

class OAuthQQSerializer(serializers.Serializer):


    mobile=serializers.RegexField(regex='1[3-9]\d{9}')
    password=serializers.CharField(max_length=20,min_length=8,write_only=True)
    sms_code=serializers.CharField(max_length=6,min_length=6,write_only=True)
    access_token=serializers.CharField(write_only=True)
    token=serializers.CharField(read_only=True)
    username=serializers.CharField(read_only=True)


    def validate(self, attrs):

        # 判断access_token
        # 解密access——token
        tjs=TJS(settings.SECRET_KEY,300)

        try:
            data=tjs.loads(attrs['access_token'])
        except:
            raise serializers.ValidationError('错误的access_token')
        # 获取openid数据
        openid=data.get('openid')
        if not openid:
            raise serializers.ValidationError('access_token失效')

        # 添加attrs属性
        attrs['openid']=openid


        # 判断短信
        # 先获取缓存中短信
        conn = get_redis_connection('verify')
        real_sms_code = conn.get('sms_code_%s' % attrs['mobile'])

        if not real_sms_code:
            raise serializers.ValidationError('短信验证码失效')

        if attrs['sms_code'] != real_sms_code.decode():
            raise serializers.ValidationError('短信验证码错误')

        # 验证用户
        try:
            user=User.objects.get(mobile=attrs['mobile'])

            if user.check_password(attrs['password']):
                attrs['user']=user
                return attrs
            raise serializers.ValidationError('密码不正确')

        except:
            return attrs

    def create(self, validated_data):
        # 获取user用户
        user=validated_data.get('user',None)

        if user is None:
            # 用户不存在，创建新用户
            user=User.objects.create_user(username=validated_data['mobile'],mobile=validated_data['mobile'],password=validated_data['password'])

        # 绑定
        OAuthQQUser.objects.create(user=user,openid=validated_data['openid'])


        # 生成token
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)

        user.token=token

        return user




