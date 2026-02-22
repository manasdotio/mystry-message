"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import axios, { AxiosError } from "axios";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { messageSchema } from "@/schemas/messageSchema";
import { ApiResponse } from "@/types/ApiResponse";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const Page = () => {
  const params = useParams<{ username: string }>();
  const username = params?.username;

  const [content, setContent] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSendMessage = async () => {
    const parsed = messageSchema.safeParse({ content });
    if (!parsed.success) {
      toast.error(parsed.error.issues[0]?.message || "Invalid message");
      return;
    }

    if (!username) {
      toast.error("Invalid profile URL");
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await axios.post<ApiResponse>("/api/send-message", {
        username,
        content,
      });
      toast.success(response.data.message || "Message sent successfully");
      setContent("");
    } catch (error) {
      const axiosError = error as AxiosError<ApiResponse>;
      toast.error(axiosError.response?.data.message || "Failed to send message");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="mx-auto my-10 w-full max-w-2xl px-4">
      <Card>
        <CardHeader>
          <CardTitle>Send anonymous message to @{username}</CardTitle>
        </CardHeader>
        <CardContent>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Write your anonymous message..."
            className="w-full min-h-36 rounded-md border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
          />
          <Button
            className="mt-4"
            onClick={handleSendMessage}
            disabled={isSubmitting}
          >
            {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Send Message"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};

export default Page;