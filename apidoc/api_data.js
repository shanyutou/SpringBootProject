define({ "api": [
  {
    "group": "Product",
    "type": "GET",
    "url": "/product/{id}",
    "title": "查询一个产品",
    "description": "<p>指定产品id , 删除产品的全部信息，包括关联的schema</p>",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "String",
            "optional": false,
            "field": "id",
            "description": "<p>产品id(必填*)</p>"
          }
        ]
      }
    },
    "success": {
      "examples": [
        {
          "title": "SuccessExample",
          "content": "HTTP/1.1 200\n{\nid: 'xxx',\nmodelId: 'xxxxx',\nname: 'xxx',\nintro: 'xxxx'\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "ErrorExample",
          "content": "HTTP/1.1 600\n具体的异常信息",
          "type": "json"
        }
      ]
    },
    "version": "0.0.0",
    "filename": "src/main/java/com/zfon/swaggerdemo/controller/HelloController.java",
    "groupTitle": "Product",
    "name": "GetProductId"
  }
] });
