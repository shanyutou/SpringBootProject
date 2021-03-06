package com.zfon.swaggerdemo;

import io.github.yedaxia.apidocs.Docs;
import io.github.yedaxia.apidocs.DocsConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SwaggerdemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SwaggerdemoApplication.class, args);

        DocsConfig config = new DocsConfig();
        config.setProjectPath("/Users/guagua/program/java/swaggerdemo"); // 项目根目录
        config.setProjectName("demo"); // 项目名称
        config.setApiVersion("V1.0");       // 声明该API的版本
        config.setDocsPath("/Users/guagua/program/java/swaggerdemo"); // 生成API 文档所在目录
        config.setAutoGenerate(Boolean.TRUE);  // 配置自动生成
        Docs.buildHtmlDocs(config); // 执行生成文档

    }

}
