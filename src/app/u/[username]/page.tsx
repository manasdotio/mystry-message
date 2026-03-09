"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useParams } from "next/navigation";
import axios, { AxiosError } from "axios";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { messageSchema } from "@/schemas/messageSchema";
import { ApiResponse } from "@/types/ApiResponse";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";

const Page = () => {
  const params = useParams<{ username: string }>();
  const username = params?.username;

  const form = useForm<z.infer<typeof messageSchema>>({
    resolver: zodResolver(messageSchema),
    defaultValues: { content: "" },
  });

  const onSubmit = async (data: z.infer<typeof messageSchema>) => {
    if (!username) {
      toast.error("Invalid profile URL");
      return;
    }

    try {
      const response = await axios.post<ApiResponse>("/api/send-message", {
        username,
        content: data.content,
      });
      toast.success(response.data.message || "Message sent successfully");
      form.reset({ content: "" });
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error(axiosError.response?.data.message || "Failed to send message");
    }
  };

  return (
    <div className="mx-auto my-10 w-full max-w-2xl px-4">
      <Card>
        <CardHeader>
          <CardTitle>Send anonymous message to @{username}</CardTitle>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)}>
              <FormField
                name="content"
                control={form.control}
                render={({ field }) => (
                  <FormItem>
                    <FormControl>
                      <textarea
                        {...field}
                        placeholder="Write your anonymous message..."
                        className="w-full min-h-36 rounded-md border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button
                type="submit"
                className="mt-4"
                disabled={form.formState.isSubmitting}
              >
                {form.formState.isSubmitting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  "Send Message"
                )}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
};

export default Page;