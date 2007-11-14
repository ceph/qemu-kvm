
void exit(int code)
{
	asm volatile("out %0, %1" : : "a"(code), "d"((short)0xf4));
}
