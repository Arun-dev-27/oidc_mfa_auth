import { Module } from '@nestjs/common';
import { ViewService } from './view.service';

/** SSR templates (views/*.html). */
@Module({
  providers: [ViewService],
  exports: [ViewService],
})
export class ViewsModule {}
