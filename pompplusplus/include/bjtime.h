#ifndef BJTime_H

#define BJTime_H

typedef unsigned char   uint8_t;
typedef struct
{
	int year;
	int month;
	int day;
	int hours;
	int minutes;
	int seconds;
}mytime_t;


void UTCToBeijing(mytime_t* time)
{
	uint8_t days = 0;
	if (time->month == 1 || time->month == 3 || time->month == 5 || time->month == 7 || time->month == 8 || time->month == 10 || time->month == 12)
	{
		days = 31;
	}
	else if (time->month == 4 || time->month == 6 || time->month == 9 || time->month == 11)
	{
		days = 30;
	}
	else if (time->month == 2)
	{
		if ((time->year % 400 == 0) || ((time->year % 4 == 0) && (time->year % 100 != 0)))
		{
			days = 29;
		}
		else
		{
			days = 28;
		}
	}
	time->hours += 8;                 
	if (time->hours >= 24)         
	{
		time->hours -= 24;
		time->day++;
		if (time->day > days)      
		{
			time->day = 1;
			time->month++;
			if (time->month > 12)  
			{
				time->year++;
			}
		}
	}

}


#endif