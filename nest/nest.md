# nest

## 基本概念

nest 是一个基于 express 等进行二次封装的 nodejs 框架，相比于 eggjs，提供了更好的 ts 支持。它主要是通过依赖注入，利用装饰器和类语法来写代码。

## 一些其他概念

### Controller

控制器主要用来匹配路由的。它通过 Controller 装饰器进行注册，可以通过 Post、Get、Head、Put、Delete、Res、Req、Body、Query 等装饰器对路由或者参数进行注册，方便我们进行参数的获取。一个控制器中可以有多个路由，每个路由进行不同的处理。

例如：

```ts
import {
    Body,
    Controller,
    Get,
    HttpException,
    HttpStatus,
    Post,
    Put,
    Query,
    UseGuards,
} from '@nestjs/common';
import { CreateArticleDto } from '../dto/createArticle.dto';
import { GetArticleByPageDto } from '../dto/getArticleByPage.dto';
import { UpdateArticleDto } from '../dto/updateArticle.dto';
import { GetArticleTitlesDto } from '../dto/getArticleTitles.dto';
import { ArticleService } from '../service/article.service';
import { to } from 'await-to-js';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ByIdDto } from 'src/logical/dto/ById.dto';
import { BaseReponseVo } from 'src/logical/vo/base.vo';
import { GetArticleByIdVo } from '../vo/getArticleById.vo';
import { GetArticleByPageVo } from '../vo/getArticleByPage.vo';
import { GetArticleTitlesVo } from '../vo/getArticleTitles.vo';
import { GetArticleTimelineVo } from '../vo/getArticleTimeline.vo';
import { GetArticleTimelineDto } from '../dto/getArticleTimeline.dto';
import { GetArticleByLatestVo } from '../vo/getArticleByLatest.vo';
import { GetArticleByLatestDto } from '../dto/getArticleByLatest.dto';
import { AuthGuard } from '@nestjs/passport';
import { UpdateDeletedDto } from 'src/logical/dto/updateDeleted.dto';
import { RbacGuard } from 'src/guard/rbac/rbac.guard';

@Controller('article')
export class ArticleController {
    constructor(private readonly articleService: ArticleService) {}
    @UseGuards(AuthGuard('jwt'))
    @UseGuards(new RbacGuard(2))
    @Post('createArticleAdmin')
    @ApiOkResponse({ description: '创建文章', type: BaseReponseVo })
    async createArticle(@Body() createArticleDto: CreateArticleDto) {
        const [err, article] = await to(this.articleService.createArticle(createArticleDto));
        if (!err) {
            if (article) {
                return { data: null, message: '添加成功' };
            } else {
                throw new HttpException('有不正确的分类或者标签', HttpStatus.BAD_REQUEST);
            }
        } else {
            throw new HttpException(
                `创建失败，出现错误：${err.message}`,
                HttpStatus.INTERNAL_SERVER_ERROR,
            );
        }
    }
}
```

### Provider

提供者就是用 Injectable 装饰器装饰的一个类。

### Service

Service 里面主要是来声明一些在路由程序中使用的方法，它也是一个提供者，需要绑定到相应的 Controller，然后就可以在控制器中使用。

例如：

```ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Category } from 'src/logical/module/category/entities/category.entity';
import { Tag } from 'src/logical/module/tag/entities/tag.entity';
import { getMoreTen, pick } from 'src/utils';
import { Repository } from 'typeorm';
import { CreateArticleDto } from '../dto/createArticle.dto';
import { UpdateArticleDto } from '../dto/updateArticle.dto';
import { Article } from '../entities/article.entity';
import { getUniqued } from 'src/utils';
import * as dayjs from 'dayjs';
import type { PaginationType } from 'src/types';

@Injectable()
export class ArticleService {
    constructor(
        @InjectRepository(Article) private articleRepository: Repository<Article>,
        @InjectRepository(Category) private categoryRepository: Repository<Category>,
        @InjectRepository(Tag) private tagRepository: Repository<Tag>,
    ) {}
    /**
     * 创建文章
     */
    async createArticle(createArticleDto: CreateArticleDto): Promise<Article> {
        const { title, content, introduction, categoryId, tagId, image } = createArticleDto;
        const addTime = dayjs().format('YYYY-MM-DD');
        const category = await this.categoryRepository.find({
            where: { isDeleted: 0, id: categoryId },
        });
        const categoriesOrTags = [
            category && category[0],
            ...(await Promise.all(
                tagId.map(async item => {
                    const tag = await this.tagRepository.find({
                        where: { isDeleted: 0, id: item },
                    });
                    return tag && tag[0];
                }),
            )),
        ];
        if (categoriesOrTags.includes(undefined)) {
            return null;
        }
        const article = pick(new Article(), {
            title,
            content,
            addTime,
            updateTime: addTime,
            introduction,
            tags: await this.tagRepository.findByIds(tagId),
            category: await this.categoryRepository.findOne({ id: categoryId }),
            image,
        });
        return this.articleRepository.save(article);
    }
}
```

### Module

一个模块中一般包含对应的 Controller、Service、Entity 等等，模块主要用来绑定这些依赖，主要绑定了以来，在 Service 或者 Controller 中才能使用。

例如：

```ts
@Module({
    imports: [TypeOrmModule.forFeature([Article, Category, Tag]), CategoryModule, TagModule],
    providers: [ArticleService],
    exports: [ArticleService, TypeOrmModule],
})
export class ArticleModule {}
```

### Entity

实体就就是一个类，但是被 Typeorm 的 Entity 等装饰器进行了装饰。它相当于是一个数据库中的表，类中的每个属性就是表中的字段。

例如：

```ts
import { Category } from 'src/logical/module/category/entities/category.entity';
import { Tag } from 'src/logical/module/tag/entities/tag.entity';
import {
    Entity,
    Column,
    ManyToMany,
    JoinTable,
    ManyToOne,
    PrimaryGeneratedColumn,
    OneToMany,
} from 'typeorm';
import { Comment } from '../../comment/entities/comment.entity';

@Entity('article')
export class Article {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    title: string;

    @Column({ length: 1000 })
    introduction: string;

    @Column()
    addTime: string;

    @Column()
    updateTime: string;

    @Column({ length: 10000 })
    content: string;

    @Column({ default: 0 })
    isDeleted: 0 | 1;

    @Column({ default: '' })
    image: string;

    @ManyToMany(() => Tag, tag => tag.articles)
    @JoinTable({ name: 'article_tag' })
    tags: Tag[];

    @ManyToOne(() => Category, category => category.articles)
    category: Category;

    @OneToMany(() => Comment, comment => comment.article)
    comments: Comment[];
}
```

### Dto

也是一个类，主要用于在路由程序中进行参数的验证。

例如：

```ts
import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CreateArticleDto {
    @ApiProperty({ description: '文章的标题', example: 'Javascript' })
    @IsString()
    @IsNotEmpty()
    readonly title: string;
    @ApiProperty({ description: '文章的内容', example: '123156456' })
    @IsString()
    @IsNotEmpty()
    readonly content: string;
    @ApiProperty({ description: '标签的id', example: [1, 2] })
    @IsArray()
    @IsNotEmpty()
    readonly tagId: number[];
    @ApiProperty({ description: '分类的id', example: 1 })
    @IsNumber()
    readonly categoryId: number;
    @ApiProperty({ description: '文章的简介', example: '215156156' })
    @IsString()
    readonly introduction: string;
    @ApiProperty({ description: '文章的简介', example: '215156156' })
    readonly image: string;
}
```

### Vo

具体的 Vo 是什么含义还有待参考，这里我主要是用来设置文档中的参数类型的。

例如：

```ts
import { ApiProperty } from '@nestjs/swagger';
import { Category } from 'src/logical/module/category/entities/category.entity';
import { Tag } from 'src/logical/module/tag/entities/tag.entity';
import { BaseReponseVo } from 'src/logical/vo/base.vo';

class ArticleDetailBaseVo {
    @ApiProperty({ description: '文章id', example: 1 })
    id: number;

    @ApiProperty({ description: '创建时间', example: '2021-07-03 19:52' })
    addTime: string;

    @ApiProperty({ description: '文章标题', example: 'Javascript' })
    title: string;

    @ApiProperty({ description: '文章简介', example: '1564864856' })
    introduction: string;

    @ApiProperty({ description: '文章的分类', example: { name: 'language', id: 1 } })
    category: Category;

    @ApiProperty({ description: '文章的标签', example: [{ name: 'JavaScript', id: 1 }] })
    tags: Tag[];

    @ApiProperty({ description: '文章的内容', example: '4654864894' })
    content: string;

    @ApiProperty({ description: '文章的图片', example: '/image/1.png' })
    image: string;
}

export class GetArticleByIdVo extends BaseReponseVo {
    @ApiProperty({ type: () => ArticleDetailBaseVo, example: ArticleDetailBaseVo })
    data: ArticleDetailBaseVo;
}
```

### Middleware

中间件主要是在路由处理程序之前调用的函数，主要来进行一个对请求对象和响应对象做一些处理的操作。

例如：

```ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { Logger } from '../../utils/log4js';


// 使用参考app.ts
@Injectable()
export class LoggerMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: () => void) {
        const code = res.statusCode; // 响应状态码
        next();
        // 组装日志信息
        const logFormat = `Method: ${req.method} \n Request original url: ${req.originalUrl} \n IP: ${req.ip} \n Status code: ${code} \n`;
        // 根据状态码，进行日志类型区分
        if (code >= 500) {
            Logger.error(logFormat);
        } else if (code >= 400) {
            Logger.warn(logFormat);
        } else {
            Logger.access(logFormat);
            Logger.log(logFormat);
        }
    }
}

// 函数式中间件
export function logger(req: Request, res: Response, next: () => any) {
    const code = res.statusCode; // 响应状态码
    next();
    // 组装日志信息
    const logFormat = ` >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    Request original url: ${req.originalUrl}
    Method: ${req.method}
    IP: ${req.ip}
    Status code: ${code}
    Parmas: ${JSON.stringify(req.params)}
    Query: ${JSON.stringify(req.query)}
    Body: ${JSON.stringify(
        req.body,
    )} \n  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  `;
    // 根据状态码，进行日志类型区分
    if (code >= 500) {
        Logger.error(logFormat);
    } else if (code >= 400) {
        Logger.warn(logFormat);
    } else {
        Logger.access(logFormat);
        Logger.log(logFormat);
    }
}
```

### ExceptionFilter

异常过滤器主要是用来捕获暴露的错误的。

例如：

```ts
// src/filter/any-exception.filter.ts
/**
 * 捕获所有异常
 */
import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Logger } from '../../utils/log4js';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();

        const status =
            exception instanceof HttpException
                ? exception.getStatus()
                : HttpStatus.INTERNAL_SERVER_ERROR;

        const logFormat = ` <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
      Request original url: ${request.originalUrl}
      Method: ${request.method}
      IP: ${request.ip}
      Status code: ${status}
      Response: ${exception} \n  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
      `;
        Logger.error(logFormat);
        response.status(status).json({
            code: status,
            message: `Service Error: ${exception}`,
            data: null,
        });
    }
}
```

或者：

```ts
// http-exception.filter.ts
import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';
import { Request, Response } from 'express';
import { Logger } from '../../utils/log4js';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
    catch(exception: HttpException, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();
        const status = exception.getStatus();

        const logFormat = ` <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    Request original url: ${request.originalUrl}
    Method: ${request.method}
    IP: ${request.ip}
    Status code: ${status}
    Response: ${exception.toString()} \n  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    `;
        Logger.info(logFormat);
        response.status(status).json({
            code: status,
            message: `${status >= 500 ? 'Service Error' : 'Client Error'}:${exception.message}`,
            data: null,
        });
    }
}
```

### Pipe

管道主要是进行转换和验证的。

例如：

```ts
// validation.pipe.ts
import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';
import { Logger } from 'src/utils/log4js';

@Injectable()
export class ValidationPipe implements PipeTransform {
    async transform(value: any, { metatype }: ArgumentMetadata) {
        if (!metatype || !this.toValidate(metatype)) {
            return value;
        }
        const object = plainToClass(metatype, value);
        const errors = await validate(object);
        if (errors.length > 0) {
            const message = Object.values(errors[0].constraints)[0];
            Logger.error(`Validation failed ${message}`);
            throw new BadRequestException(`Validation failed ${message}`);
        }
        return value;
    }
    private toValidate(metatype: any): boolean {
        const types: any[] = [String, Boolean, Number, Array, Object];
        return !types.includes(metatype);
    }
}
```

### Guide

守卫主要是进行权限控制的

例如：

```ts
// rbac.guide.ts
import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class RbacGuard implements CanActivate {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(private readonly role: number) {}
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const request = context.switchToHttp().getRequest();
        const { method, query, body } = request as {
            method: string;
            query: { role: number };
            body: { role: number };
        };
        const role = method.toLowerCase() === 'get' ? query?.role : body?.role;
        if (!role || Number(role) < this.role) {
            throw new ForbiddenException('你没有权限进行操作');
        }
        return true;
    }
}
```

### Interceptor

拦截器的功能就比较多了，它主要作用在处理请求前和处理响应后。

例如：

```ts
// src/interceptor/transform.interceptor.ts
import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Logger } from '../../utils/log4js';

@Injectable()
export class LoggerInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        const { req } = context.getArgByIndex(1);
        return next.handle().pipe(
            map(data => {
                const logFormat = ` <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    Request original url: ${req.originalUrl}
    Method: ${req.method}
    IP: ${req.ip}
    User: ${JSON.stringify(req.user)}
    Response data:\n ${JSON.stringify(data)}
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<`;
                Logger.info(logFormat);
                Logger.access(logFormat);
                return data;
            }),
        );
    }
}
```

```ts
import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { classToPlain } from 'class-transformer';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CodeEnum } from 'src/enums/code.enum';

@Injectable()
export class TransformInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        return next.handle().pipe(
            map((data: { data: any; message: string }) => {
                console.log({ data });
                return {
                    data: classToPlain(data?.data ?? null),
                    code: CodeEnum.SUCCESS,
                    message: data?.message || '操作成功',
                };
            }),
        );
    }
}
```

app.ts

```ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { logger } from './middleware/logger/logger.middleware';
import * as express from 'express';
import { LoggerInterceptor } from './interceptor/logger/logger.interceptor';
import { AllExceptionsFilter } from './filter/any-exception/anyException.filter';
import { HttpExceptionFilter } from './filter/http-exception/http-exception.filter';
import { TransformInterceptor } from './interceptor/transform/transform.interceptor';
import { ValidationPipe } from './pipe/validation/validation.pipe';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as helmet from 'helmet';
// import { ClassSerializerInterceptor } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create<NestExpressApplication>(AppModule);
    //允许跨域请求
    app.enableCors();

    // Web漏洞的
    app.use(helmet());
    // 添加前缀为api
    app.setGlobalPrefix('api');
    // 监听所有的请求路由，并打印日志
    app.use(express.json()); // For parsing application/json
    app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded
    app.use(logger);
    // 静态资源托管
    app.useStaticAssets(join(__dirname, '..', 'public'));
    // 使用全局拦截器打印出参
    app.useGlobalInterceptors(new LoggerInterceptor());
    // app.useGlobalInterceptors(new ClassSerializerInterceptor());
    app.useGlobalInterceptors(new TransformInterceptor());
    app.useGlobalPipes(new ValidationPipe());
    app.useGlobalFilters(new AllExceptionsFilter());
    // 过滤处理 HTTP 异常
    app.useGlobalFilters(new HttpExceptionFilter());
    if (process.env.NODE_ENV != 'production') {
        // 配置swagger
        const options = new DocumentBuilder()
            .setTitle('The nest store api')
            .setDescription('The nest store api discription')
            .setVersion('1.0')
            .addTag('test')
            .build();
        const document = SwaggerModule.createDocument(app, options);
        SwaggerModule.setup('api-doc', app, document);
    }
    await app.listen(7000);
}
bootstrap();
```
